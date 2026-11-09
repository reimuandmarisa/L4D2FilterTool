// ============================================================================
//  NameLayer —— 内置「名字层」：让 FilterTool 自己按服务器名丢包
//
//  背景：原来"按名字拦"是 SteamServerFilter.exe 干的，FilterTool 只负责写规则文件。
//  代价是它一旦自己退出，名字层就静默失效；而且 FilterTool 的"发现新端点"
//  也依赖它写的日志。本文件把这层搬进 FilterTool，彻底解耦。
//
//  原理（与 SteamServerFilter 等价）：
//    1. 开一个 WinDivert 句柄，过滤器就是 `udp`（双向）；
//    2. 每个 UDP 包在用户态看一眼：
//         · 命中 IP 拦截清单（含 !端口 例外）    → 丢
//         · 命中"已按名字封掉的端点"             → 丢
//         · 是 A2S_INFO 应答(FF FF FF FF 49)     → 解析服名 → 按 block_rules.txt 匹配
//                                                  命中：丢，并把这个端点记进封禁集
//         · 其余                                → 原样重注入(WinDivertSend)
//    3. 顺手记录"本机查询过哪些端点"（A2S 请求 FF FF FF FF 54）——这就不必再
//       依赖 SteamServerFilter 的日志来发现新服了。
//
//  规则语义与引擎完全一致（复用 Engine.ReadEngineRules）：UTF-8、空行跳过、
//  Ordinal 去重、**大小写敏感**、**非锚定**、只匹配 A2S 的 Name 字段。
//
//  Source 未压缩分片（FE FF FF FF）在有界缓存中重组；仅完成片可按名字丢弃。
//  压缩 / GoldSrc / IPv4 IP 分片 / IPv6 不处理，保持放行。
//
//  与 IP 层句柄的关系：两个 WinDivert 句柄若过滤器相交，会按优先级抢包。
//  这里让两者【不相交】—— 名字层用 `udp`，IP 层用 `<地址条件> and not udp`，
//  因此不会互相抢占。
// ============================================================================

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;

namespace SteamServerFilterIpBlock
{
    internal static class NameLayer
    {
        private const int LAYER_NETWORK = 0;
        private const int SHUTDOWN_BOTH = 3;

        [DllImport("WinDivert.dll", SetLastError = true)]
        private static extern IntPtr WinDivertOpen(string filter, int layer, short priority, ulong flags);
        [DllImport("WinDivert.dll", SetLastError = true)]
        private static extern bool WinDivertRecv(IntPtr handle, byte[] packet, uint packetLen, out uint readLen, IntPtr addr);
        [DllImport("WinDivert.dll", SetLastError = true)]
        private static extern bool WinDivertSend(IntPtr handle, byte[] packet, uint packetLen, out uint writeLen, IntPtr addr);
        [DllImport("WinDivert.dll", SetLastError = true)]
        private static extern bool WinDivertSetParam(IntPtr handle, int param, ulong value);
        [DllImport("WinDivert.dll", SetLastError = true)]
        private static extern bool WinDivertShutdown(IntPtr handle, int how);
        [DllImport("WinDivert.dll", SetLastError = true)]
        private static extern bool WinDivertClose(IntPtr handle);
        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern IntPtr LoadLibraryW(string path);

        public static string LastError = "";
        public static long Seen, Reinjected, Dropped, NameHits;
        public static string LastHit = "";

        private static IntPtr _handle = new IntPtr(-1);
        private static Thread _thread;
        private static volatile bool _running;

        /// <summary>已按名字封掉的端点。键 = (ip &lt;&lt; 16) | port，避免每个包拼字符串（V-31）。</summary>
        private static readonly HashSet<ulong> _blocked = new HashSet<ulong>();
        private static readonly Dictionary<ulong, string> _blockedInfo = new Dictionary<ulong, string>();
        private static readonly object _lock = new object();

        // Source split replies are kept in a separate bounded cache.  It has no
        // file/logging side effects and is also usable by SelfTest with a fake clock.
        private static readonly SourceSplitCache _sourceSplits =
            new SourceSplitCache(SourceSplitNowMilliseconds);

        private static long SourceSplitNowMilliseconds()
        {
            long ticks = Stopwatch.GetTimestamp();
            long whole = ticks / Stopwatch.Frequency;
            long remainder = ticks % Stopwatch.Frequency;
            return whole * 1000L + (remainder * 1000L) / Stopwatch.Frequency;
        }

        public static ulong Key(string ip, int port)
        {
            uint v; uint dummy;
            if (!IpEngine.TryParseRange(ip, out v, out dummy)) return 0;
            return ((ulong)v << 16) | (uint)(port & 0xFFFF);
        }

        private static List<Regex> _rules = new List<Regex>();
        private static List<string> _ruleTexts = new List<string>();
        private static readonly TimeSpan RxTimeout = TimeSpan.FromSeconds(2);

        // P1：名字层直接处理外部数据（规则文件、A2S 服名、抓到的端点），必须设硬预算，
        // 否则一个超大规则文件或恶意服名就能让每个 UDP 包都卡住/让内存无限增长。
        public const int MaxRules = 200;
        public const int MaxTotalPatternChars = 20000;
        public const int MaxSeen = 5000;
        public const int MaxBlocked = 10000;
        private static readonly TimeSpan MatchBudget = TimeSpan.FromMilliseconds(30);
        private static readonly TimeSpan SeenTtl = TimeSpan.FromDays(7);
        public static long RuleLimitDropped, MatchBudgetHits, SeenDropped, BlockedDropped;

        public static bool IsRunning { get { return _running; } }
        public static int BlockedCount { get { lock (_lock) return _blocked.Count; } }

        public static string BlockedFile { get { return Path.Combine(IpEngine.Root, "name_layer_blocked.txt"); } }
        public static string SeenFile { get { return Path.Combine(IpEngine.Root, "name_layer_seen.tsv"); } }
        public static string FlagFile { get { return Path.Combine(IpEngine.Root, "name_layer.txt"); } }

        // ---- 拦截模式：both = IP 清单 + 名字规则；name = 只按名字拦，完全不匹配 IP ----
        public static string ModeFile { get { return Path.Combine(IpEngine.Root, "block_mode.txt"); } }

        // V-35: 这个属性会在【每个 UDP 包】上求值，绝不能每包读文件 ——
        // 与 ParsedRanges 同样的策略：缓存布尔值，文件时间戳最多每秒查一次。
        private static bool _nameOnlyCache;
        private static DateTime _nameOnlyStamp = DateTime.MinValue;
        private static DateTime _nameOnlyCheckedAt = DateTime.MinValue;

        private static bool ReadModeFile()
        {
            try
            {
                if (!File.Exists(ModeFile)) return false;
                return SafeFile.Read(ModeFile).Trim().ToLowerInvariant().StartsWith("name");
            }
            catch { return false; }
        }

        /// <summary>true = 纯名字模式（ip_block.txt 不参与拦截，避免"按 IP 连坐"误伤）。</summary>
        public static bool NameOnlyMode
        {
            get
            {
                var now = DateTime.Now;
                if ((now - _nameOnlyCheckedAt).TotalSeconds >= 1.0)
                {
                    _nameOnlyCheckedAt = now;
                    try
                    {
                        // 3.2：config.ini 的 mode 优先；没有该键才看 block_mode.txt
                        var cm = Config.Get("mode");
                        if (cm != null) { _nameOnlyCache = cm.Trim().ToLowerInvariant().StartsWith("name"); return _nameOnlyCache; }
                        var st = File.Exists(ModeFile) ? File.GetLastWriteTime(ModeFile) : DateTime.MinValue;
                        if (st != _nameOnlyStamp) { _nameOnlyStamp = st; _nameOnlyCache = ReadModeFile(); }
                    }
                    catch { }
                }
                return _nameOnlyCache;
            }
            set
            {
                _nameOnlyCache = value;          // 本进程立刻生效，不必等缓存刷新

                // 不变量：纯名字模式下 ip_block.txt 不参与拦截，全指望名字层 ——
                // 所以模式一旦为 name，名字层开关必须自动置 on（不再依赖各调用点自觉）。
                if (value && !Enabled) Enabled = true;
                _nameOnlyCheckedAt = DateTime.Now;
                SafeFile.Write(ModeFile,
                    (value ? "name" : "both") + "\r\n" +
                    "# both = IP 清单 + 名字规则都生效（默认）\r\n" +
                    "# name = 只按服务器名拦；ip_block.txt 完全不参与，不会有按 IP 连坐的误伤\r\n" +
                    "# 改完保存即可：常驻进程 5 秒内自动切换。\r\n");
                try { _nameOnlyStamp = File.Exists(ModeFile) ? File.GetLastWriteTime(ModeFile) : DateTime.MinValue; } catch { }
                try { Config.Set("mode", value ? "name" : "both"); } catch { }   // 3.2
            }
        }

        public static string ModeName { get { return NameOnlyMode ? "纯名字（不用 IP 清单）" : "IP 清单 + 名字规则"; } }

        /// <summary>名字层开关（存在 name_layer.txt 且内容为 on）。</summary>
        public static bool Enabled
        {
            get
            {
                try
                {
                    var cv = Config.GetBool("name-layer");      // 3.2：config.ini 优先
                    if (cv.HasValue) return cv.Value;
                    if (!File.Exists(FlagFile)) return false;
                    return SafeFile.Read(FlagFile).Trim().ToLowerInvariant().StartsWith("on");
                }
                catch { return false; }
            }
            set
            {
                // 自动联动（与 NameOnlyMode 的 setter 成对，界面与 CLI 共用）：
                // 「只启动名字层」必须由名字层执行 —— 关掉名字层时不能留着该模式，
                // 否则会造出"模式=只启动名字层、名字层=关"的矛盾状态。
                if (!value && NameOnlyMode) NameOnlyMode = false;   // 用 getter：新进程里缓存还是初始值，直接读字段会漏掉联动
                SafeFile.Write(FlagFile,
                    (value ? "on" : "off") + "\r\n# 内置名字层开关：on = FilterTool 自己按服务器名丢包（可替代 SteamServerFilter 的名字层）\r\n");
                try { Config.Set("name-layer", value ? "on" : "off"); } catch { }   // 3.2
            }
        }

        // ------------------------------------------------------------------ 规则
        public static void LoadRules()
        {
            _sourceSplits.Clear();
            _rules = new List<Regex>();
            _ruleTexts = new List<string>();
            int totalChars = 0, dropped = 0;
            try
            {
                foreach (var r in SteamServerFilterRules.Engine.ReadEngineRules())
                {
                    if (_rules.Count >= MaxRules || totalChars + r.Length > MaxTotalPatternChars)
                    {
                        dropped++;
                        continue;
                    }
                    try
                    {
                        _rules.Add(new Regex(r, RegexOptions.None, RxTimeout));   // 与引擎一致：无 IgnoreCase、非锚定
                        _ruleTexts.Add(r);
                        totalChars += r.Length;
                    }
                    catch { }   // 非法正则忽略（引擎也是 try/catch）
                }
            }
            catch { }
            if (dropped > 0)
            {
                RuleLimitDropped += dropped;
                LastError = "名字规则超过预算（最多 " + MaxRules + " 条 / " + MaxTotalPatternChars + " 字符），已忽略 " + dropped + " 条。";
            }
        }

        /// <summary>用指定规则集匹配（自检用：避免受当前 block_rules.txt 影响）。</summary>
        public static string MatchRuleWithRules(List<string> rules, string name)
        {
            if (rules == null || string.IsNullOrEmpty(name)) return null;
            foreach (var r in rules)
            {
                try
                {
                    if (System.Text.RegularExpressions.Regex.IsMatch(name, r,
                            System.Text.RegularExpressions.RegexOptions.None, RxTimeout)) return r;
                }
                catch { }
            }
            return null;
        }

        /// <summary>按引擎语义匹配服名，返回命中的规则文本（没有则 null）。总耗时受 30ms 预算限制。</summary>
        public static string MatchRule(string name)
        {
            if (string.IsNullOrEmpty(name)) return null;
            var sw = Stopwatch.StartNew();
            for (int i = 0; i < _rules.Count; i++)
            {
                if ((i & 7) == 7 && sw.Elapsed > MatchBudget)
                {
                    MatchBudgetHits++;
                    break;
                }
                try { if (_rules[i].IsMatch(name)) return _ruleTexts[i]; }
                catch { }
            }
            return null;
        }

        // ------------------------------------------------------------------ 封禁集
        public static void ReloadBlocked() { LoadBlocked(); }

        private static void LoadBlocked()
        {
            // 封禁是"名字规则"的派生结果：规则被删掉后，由它封的端点应自动失效，
            // 否则删了规则这些服还是连不上（实测踩过这个坑）。
            var currentRules = new HashSet<string>(
                SteamServerFilterRules.Engine.ReadEngineRules(), StringComparer.Ordinal);
            lock (_lock)
            {
                _blocked.Clear(); _blockedInfo.Clear();
                foreach (var l in SafeFile.Read(BlockedFile).Replace("\r\n", "\n").Split('\n'))
                {
                    if (l.Trim().Length == 0 || l.TrimStart().StartsWith("#")) continue;
                    var p = l.Split('\t');
                    var ep = p.Length > 0 ? p[0].Trim() : "";
                    if (ep.Length == 0) continue;
                    var nm = p.Length > 1 ? p[1] : "";
                    var ru = p.Length > 2 ? p[2] : "";
                    if (ru.Length > 0 && !currentRules.Contains(ru)) continue;   // 规则没了 → 派生封禁失效
                    var c = ep.LastIndexOf(':');
                    if (c <= 0) continue;
                    // V-38: 这个表支持手工编辑，端口写错不能把整个常驻进程带崩 —— 坏行跳过
                    int pk;
                    if (!int.TryParse(ep.Substring(c + 1), out pk)) continue;
                    var k = Key(ep.Substring(0, c), pk);
                    if (k == 0) continue;
                    if (_blocked.Count >= MaxBlocked) { BlockedDropped++; break; }
                    _blocked.Add(k);
                    _blockedInfo[k] = nm + (ru.Length > 0 ? ("  [规则 " + ru + "]") : "");
                }
            }
        }

        public static List<KeyValuePair<string, string>> BlockedList()
        {
            lock (_lock)
                return _blockedInfo.Select(kv => new KeyValuePair<string, string>(KeyToEndpoint(kv.Key), kv.Value))
                                   .OrderBy(kv => kv.Key, StringComparer.Ordinal).ToList();
        }

        public static string KeyToEndpoint(ulong k)
        {
            return IpEngine.UintToIp((uint)(k >> 16)) + ":" + (int)(k & 0xFFFF);
        }

        private static string ipOf(string ep) { var c = ep.LastIndexOf(':'); return c > 0 ? ep.Substring(0, c) : ep; }
        private static int portOf(string ep) { var c = ep.LastIndexOf(':'); int p; return c > 0 && int.TryParse(ep.Substring(c + 1), out p) ? p : 0; }

        private static void AddBlocked(string ep, string name, string rule)
        {
            lock (_lock)
            {
                var kk = Key(ipOf(ep), portOf(ep));
                if (kk == 0) return;
                if (!_blocked.Contains(kk) && _blocked.Count >= MaxBlocked) { BlockedDropped++; return; }
                if (!_blocked.Add(kk)) return;
                _blockedInfo[kk] = name + "  [规则 " + rule + "]";
            }
            LastHit = ep + "  " + name;
            // V-31: 落盘交给写线程 —— 捕获线程绝不做磁盘/互斥量操作，否则全机 UDP 会排队
            _blockedDirty = true;
            try { _writerSignal.Set(); } catch { }
        }

        /// <summary>把封禁表按内存里的有效集写盘（只在写线程调用）。</summary>
        private static void FlushBlocked()
        {
            try
            {
                List<KeyValuePair<ulong, string>> snap;
                lock (_lock) snap = _blockedInfo.OrderBy(kv => kv.Key).ToList();
                var sb = new StringBuilder();
                sb.Append("# 内置名字层按服务器名封掉的端点（ip:port <TAB> 服名 <TAB> 命中规则）\r\n");
                sb.Append("# 规则被删掉后这些条目会自动失效；也可以直接删行。\r\n");
                foreach (var kv in snap)
                {
                    var info = kv.Value;
                    var ru = "";
                    var i = info.IndexOf("[规则 ");
                    if (i >= 0) { ru = info.Substring(i + 4).TrimEnd(']', ' '); info = info.Substring(0, i).Trim(); }
                    sb.Append(KeyToEndpoint(kv.Key)).Append('\t').Append(info).Append('\t').Append(ru).Append("\r\n");
                }
                SafeFile.Write(BlockedFile, sb.ToString());
            }
            catch { }
        }

        // ------------------------------------------------------------------ 启动/停止
        public static string Start()
        {
            Stop();
            LastError = "";
            Seen = Reinjected = Dropped = NameHits = 0;
            if (!IpEngine.BlockerReady()) { LastError = "找不到 WinDivert.dll"; return LastError; }
            try { LoadLibraryW(Path.GetFullPath(IpEngine.BlockerDllPath())); } catch { }
            LoadRules();
            if (_rules.Count == 0) { LastError = "block_rules.txt 里没有可用规则"; return LastError; }
            LoadBlocked();

            var h = WinDivertOpen("udp", LAYER_NETWORK, 0, 0);
            if (h == new IntPtr(-1))
            {
                var err = Marshal.GetLastWin32Error();
                LastError = "WinDivertOpen(\"udp\") 失败 (err " + err + ")";
                return LastError;
            }
            TuneQueue(h);            // 1.2
            _handle = h;
            _running = true;
            _writerStop = false;
            _writer = new Thread(WriterLoop) { IsBackground = true, Name = "name-layer-writer" };
            _writer.Start();
            _thread = new Thread(Loop) { IsBackground = true, Name = "name-layer" };
            _thread.Start();
            return "OK";
        }

        /// <summary>1.2：把队列调大 —— 捕获线程偶发变慢（GC/磁盘）时不再静默丢包。</summary>
        public static void TuneQueue(IntPtr h)
        {
            try { WinDivertSetParam(h, 0, 16384); } catch { }   // QUEUE_LENGTH
            try { WinDivertSetParam(h, 1, 8000); } catch { }    // QUEUE_TIME(ms)
        }

        public static void Stop()
        {
            _running = false;
            if (_handle != new IntPtr(-1))
            {
                try { WinDivertShutdown(_handle, SHUTDOWN_BOTH); } catch { }
                try { WinDivertClose(_handle); } catch { }
                _handle = new IntPtr(-1);
            }
            try { if (_thread != null) _thread.Join(1500); } catch { }
            _thread = null;
            _sourceSplits.Clear();

            // 停掉写线程，最后一次落盘（此时只剩本线程，V-34 的竞态不复存在）
            _writerStop = true;
            try { _writerSignal.Set(); } catch { }
            try { if (_writer != null) _writer.Join(2000); } catch { }
            _writer = null;
            try { FlushSeen(); } catch { }
            try { FlushBlocked(); } catch { }
        }

        // ------------------------------------------------------------------ 主循环
        private static void Loop()
        {
            var buf = new byte[65535];
            var addr = Marshal.AllocHGlobal(64);
            uint read, written;
            try
            {
                while (_running)
                {
                    if (!WinDivertRecv(_handle, buf, (uint)buf.Length, out read, addr))
                    {
                        if (!_running) break;
                        int error = Marshal.GetLastWin32Error();
                        if (error == 6 || error == 995 || error == 232)
                        {
                            LastError = "WinDivertRecv 失败 (err " + error + ")";
                            break;
                        }
                        Thread.Sleep(1);
                        continue;
                    }
                    Interlocked.Increment(ref Seen);
                    bool drop = false;
                    try { drop = Decide(buf, (int)read); }
                    catch { }

                    if (drop)
                    {
                        Interlocked.Increment(ref Dropped);   // 不重注入 = 丢弃
                        continue;
                    }
                    if (!WinDivertSend(_handle, buf, read, out written, addr))
                        Interlocked.Increment(ref Dropped);   // 重注入失败只能算丢（并计数，便于发现异常）
                    else Interlocked.Increment(ref Reinjected);
                }
            }
            catch (Exception ex) { LastError = "名字层收包线程退出：" + ex.Message; }
            finally
            {
                _running = false;
                Marshal.FreeHGlobal(addr);
            }
        }

        // ------------------------------------------------------------------ 单包判定
        /// <summary>单包判定（主循环与 --selftest 共用）。</summary>
        public static bool DecidePacket(byte[] b, int len) { return Decide(b, len); }

        private static bool Decide(byte[] b, int len)
        {
            if (b == null || len < 28 || len > b.Length) return false;
            if ((b[0] >> 4) != 4) return false;                 // 只处理 IPv4
            int ihl = (b[0] & 0x0F) * 4;
            if (ihl < 20 || len < ihl + 8) return false;
            int ipLength = (b[2] << 8) | b[3];
            if (ipLength < ihl + 8 || ipLength > len) return false;
            if (b[9] != 17) return false;                       // 只处理 UDP（过滤器也只抓 udp）
            int fragmentFlags = (b[6] << 8) | b[7];
            // MF / offset: IPv4 fragmentation is not A2S fragmentation.  Never
            // interpret a fragment's bytes as ports or partial A2S payload.
            if ((fragmentFlags & 0xBFFF) != 0) return false;     // 保留位 / MF / offset；DF 允许
            // 1.1：直接从字节算整数，不再为每个包拼两个 IP 字符串（原来每包 2 次堆分配）
            uint su = (uint)((b[12] << 24) | (b[13] << 16) | (b[14] << 8) | b[15]);
            uint du = (uint)((b[16] << 24) | (b[17] << 16) | (b[18] << 8) | b[19]);
            int sport = (b[ihl] << 8) | b[ihl + 1];
            int dport = (b[ihl + 2] << 8) | b[ihl + 3];
            int udpLength = (b[ihl + 4] << 8) | b[ihl + 5];
            int udpAvailable = ipLength - ihl;
            int po = ihl + 8;
            // Datagram validity is distinct from a short A2S payload: malformed
            // or truncated UDP must be released even on a blocked endpoint.
            if (udpLength < 8 || udpLength != udpAvailable) return false;

            // 1) IP/endpoint checks intentionally precede payload-length checks:
            // even a short UDP packet must not bypass an existing IP/endpoint block.
            if (!NameOnlyMode && IpEngine.IsPacketBlockedFastU(su, sport, du, dport)) return true;

            // 2) 已按名字封掉的端点（双向，ulong 键，无字符串分配）
            lock (_lock)
            {
                if (_blocked.Contains(((ulong)su << 16) | (uint)sport) ||
                    _blocked.Contains(((ulong)du << 16) | (uint)dport))
                    return true;
            }

            int plen = udpLength - 8;

            // 3) 非 A2S 或过短载荷不能解析名字，但不能影响前面的拦截判定。
            if (plen < 5) return false;

            // 4) A2S 报文。Source split packets carry a real split header and
            // are reassembled before the normal FFFFFFFF49 name path is used.
            if (b[po] == 0xFE && b[po + 1] == 0xFF &&
                b[po + 2] == 0xFF && b[po + 3] == 0xFF)
            {
                var whole = _sourceSplits.Feed(su, sport, du, dport, b, po, plen);
                return whole != null && HandleA2sPayload(whole, 0, whole.Length, su, sport, du, dport);
            }
            return HandleA2sPayload(b, po, plen, su, sport, du, dport);
        }

        private static bool HandleA2sPayload(byte[] b, int po, int plen,
            uint su, int sport, uint du, int dport)
        {
            if (b == null || po < 0 || plen < 5 || po > b.Length || plen > b.Length - po)
                return false;
            if (b[po] != 0xFF || b[po + 1] != 0xFF || b[po + 2] != 0xFF || b[po + 3] != 0xFF)
                return false;
            byte kind = b[po + 4];
            if (kind == 0x49 && plen > 7)                   // 'I' = A2S_INFO 应答
            {
                int e = -1;
                for (int k = po + 6; k < po + plen; k++) if (b[k] == 0) { e = k; break; }
                if (e > po + 6)
                {
                    var name = Encoding.UTF8.GetString(b, po + 6, e - (po + 6)).Trim();
                    if (name.Length > 0)
                    {
                        var ep = IpEngine.UintToIp(su) + ":" + sport;   // 应答来自服务器
                        RecordSeen(ep, name);
                        var rule = MatchRule(name);
                        if (rule != null)
                        {
                            AddBlocked(ep, name, rule);
                            Interlocked.Increment(ref NameHits);
                            return true;                    // 丢这一包；该端点后续流量也走第 2 步被丢
                        }
                    }
                }
            }
            else if (kind == 0x54)                          // 'T' = A2S_INFO 请求
            {
                RecordSeen(IpEngine.UintToIp(du) + ":" + dport, "");
            }
            // 0x41('A') challenge and malformed/unsupported payloads pass.
            return false;
        }

        /// <summary>
        /// Bounded Source (uncompressed) split reassembler.  The clock is injected
        /// so SelfTest can exercise TTL and pruning without sleeping.
        /// </summary>
        internal sealed class SourceSplitCache
        {
            internal const int MaxFragments = 32;
            internal const int MaxSessionBytes = 64 * 1024;
            internal const int MaxGlobalBytes = 4 * 1024 * 1024;
            internal const int MaxSessions = 256;
            internal const long LifetimeMilliseconds = 2000;
            private const int HeaderBytes = 12;

            private readonly Func<long> _nowMilliseconds;
            private readonly object _gate = new object();
            private readonly Dictionary<SplitKey, SplitSession> _sessions =
                new Dictionary<SplitKey, SplitSession>();
            private int _cachedBytes;

            internal SourceSplitCache(Func<long> nowMilliseconds)
            {
                _nowMilliseconds = nowMilliseconds ?? (() => DateTime.UtcNow.Ticks / TimeSpan.TicksPerMillisecond);
            }

            internal int SessionCount { get { lock (_gate) { PruneLocked(Now()); return _sessions.Count; } } }
            internal int CachedBytes { get { lock (_gate) { PruneLocked(Now()); return _cachedBytes; } } }

            private long Now()
            {
                try { return _nowMilliseconds(); }
                catch { return DateTime.UtcNow.Ticks / TimeSpan.TicksPerMillisecond; }
            }

            internal void Clear()
            {
                lock (_gate)
                {
                    _sessions.Clear();
                    _cachedBytes = 0;
                }
            }

            internal void Prune()
            {
                lock (_gate) PruneLocked(Now());
            }

            private void PruneLocked(long now)
            {
                if (_sessions.Count == 0) return;
                List<SplitKey> expired = null;
                foreach (var kv in _sessions)
                {
                    if (now - kv.Value.CreatedAt >= LifetimeMilliseconds)
                    {
                        if (expired == null) expired = new List<SplitKey>();
                        expired.Add(kv.Key);
                    }
                }
                if (expired == null) return;
                foreach (var key in expired) RemoveLocked(key);
            }

            private void RemoveLocked(SplitKey key)
            {
                SplitSession old;
                if (!_sessions.TryGetValue(key, out old)) return;
                _sessions.Remove(key);
                _cachedBytes -= old.Bytes;
                if (_cachedBytes < 0) _cachedBytes = 0;
            }

            /// <summary>
            /// Feed one complete UDP payload, including its 12-byte Source split
            /// header.  Returns a newly assembled FFFFFFFF49 payload only when the
            /// session completes; all other results are null and must be released.
            /// </summary>
            internal byte[] Feed(uint sourceIp, int sourcePort, uint destinationIp, int destinationPort,
                byte[] packet, int offset, int length)
            {
                if (packet == null || offset < 0 || length < 0 || offset > packet.Length - length ||
                    sourcePort < 0 || sourcePort > 65535 || destinationPort < 0 || destinationPort > 65535)
                    return null;
                long now = Now();
                // Eight bytes are enough to identify and discard an existing
                // session when the rest of the split header is truncated.
                if (length < 8 || packet[offset] != 0xFE || packet[offset + 1] != 0xFF ||
                    packet[offset + 2] != 0xFF || packet[offset + 3] != 0xFF)
                    return null;

                uint requestId = (uint)(packet[offset + 4] |
                    (packet[offset + 5] << 8) | (packet[offset + 6] << 16) | (packet[offset + 7] << 24));
                var key = new SplitKey(sourceIp, sourcePort, destinationIp, destinationPort, requestId);
                lock (_gate)
                {
                    PruneLocked(now);
                    // Source uses the high request-id bit for compression.  Such
                    // packets, and GoldSrc's different split layout, pass through.
                    if ((requestId & 0x80000000U) != 0)
                    {
                        RemoveLocked(key);
                        return null;
                    }
                    if (length < HeaderBytes)
                    {
                        RemoveLocked(key);
                        return null;
                    }

                    int total = packet[offset + 8];
                    int index = packet[offset + 9];
                    int declaredSize = packet[offset + 10] | (packet[offset + 11] << 8);
                    int bodyLength = length - HeaderBytes;
                    if (total < 1 || total > MaxFragments || index < 0 || index >= total ||
                        declaredSize <= 0 || declaredSize > 65535 || bodyLength <= 0 ||
                        bodyLength > declaredSize || bodyLength > MaxSessionBytes)
                    {
                        RemoveLocked(key);
                        return null;
                    }

                    SplitSession session;
                    if (!_sessions.TryGetValue(key, out session))
                    {
                        if (_sessions.Count >= MaxSessions || _cachedBytes > MaxGlobalBytes - bodyLength)
                            return null;
                        session = new SplitSession(total, declaredSize, now);
                        _sessions.Add(key, session);
                    }
                    else if (session.Total != total || session.Size != declaredSize ||
                        now - session.CreatedAt >= LifetimeMilliseconds)
                    {
                        RemoveLocked(key);
                        return null;
                    }

                    byte[] prior;
                    if (session.Fragments.TryGetValue(index, out prior))
                    {
                        if (prior.Length != bodyLength || !BytesEqual(prior, packet, offset + HeaderBytes, bodyLength))
                        {
                            RemoveLocked(key);
                            return null;
                        }
                        // Identical duplicates are accepted without extending TTL
                        // or allocating another buffer.
                    }
                    else
                    {
                        if (session.Bytes > MaxSessionBytes - bodyLength ||
                            _cachedBytes > MaxGlobalBytes - bodyLength)
                        {
                            RemoveLocked(key);
                            return null;
                        }
                        var copy = new byte[bodyLength];
                        Buffer.BlockCopy(packet, offset + HeaderBytes, copy, 0, bodyLength);
                        session.Fragments.Add(index, copy);
                        session.Bytes += bodyLength;
                        _cachedBytes += bodyLength;
                    }

                    if (session.Fragments.Count != session.Total) return null;
                    if (session.Bytes < 5 || session.Bytes > MaxSessionBytes)
                    {
                        RemoveLocked(key);
                        return null;
                    }
                    var result = new byte[session.Bytes];
                    int at = 0;
                    for (int i = 0; i < session.Total; i++)
                    {
                        if (!session.Fragments.TryGetValue(i, out prior))
                        {
                            RemoveLocked(key);
                            return null;
                        }
                        Buffer.BlockCopy(prior, 0, result, at, prior.Length);
                        at += prior.Length;
                    }
                    RemoveLocked(key);
                    if (result[0] != 0xFF || result[1] != 0xFF || result[2] != 0xFF ||
                        result[3] != 0xFF || result[4] != 0x49)
                        return null;
                    return result;
                }
            }

            private static bool BytesEqual(byte[] a, byte[] b, int offset, int length)
            {
                if (a == null || b == null || a.Length != length || offset < 0 || offset > b.Length - length)
                    return false;
                for (int i = 0; i < length; i++) if (a[i] != b[offset + i]) return false;
                return true;
            }

            private struct SplitKey : IEquatable<SplitKey>
            {
                private readonly uint SourceIp, DestinationIp, RequestId;
                private readonly ushort SourcePort, DestinationPort;

                internal SplitKey(uint sourceIp, int sourcePort, uint destinationIp, int destinationPort, uint requestId)
                {
                    SourceIp = sourceIp; SourcePort = (ushort)sourcePort;
                    DestinationIp = destinationIp; DestinationPort = (ushort)destinationPort;
                    RequestId = requestId;
                }

                public bool Equals(SplitKey other)
                {
                    return SourceIp == other.SourceIp && SourcePort == other.SourcePort &&
                        DestinationIp == other.DestinationIp && DestinationPort == other.DestinationPort &&
                        RequestId == other.RequestId;
                }

                public override bool Equals(object obj) { return obj is SplitKey && Equals((SplitKey)obj); }
                public override int GetHashCode()
                {
                    unchecked
                    {
                        int h = (int)SourceIp;
                        h = (h * 397) ^ SourcePort; h = (h * 397) ^ (int)DestinationIp;
                        h = (h * 397) ^ DestinationPort; return (h * 397) ^ (int)RequestId;
                    }
                }
            }

            private sealed class SplitSession
            {
                internal readonly int Total;
                internal readonly int Size;
                internal readonly long CreatedAt;
                internal int Bytes;
                internal readonly Dictionary<int, byte[]> Fragments = new Dictionary<int, byte[]>();

                internal SplitSession(int total, int size, long createdAt)
                {
                    Total = total; Size = size; CreatedAt = createdAt;
                }
            }
        }

        // Internal-only hooks for SelfTest. They expose no file, socket, or WinDivert behavior.
        internal static SourceSplitCache CreateSourceSplitCacheForTest(Func<long> nowMilliseconds)
        {
            return new SourceSplitCache(nowMilliseconds);
        }

        internal static void ResetPacketTestState()
        {
            _sourceSplits.Clear();
            lock (_lock)
            {
                _blocked.Clear();
                _blockedInfo.Clear();
            }
            lock (_seen)
            {
                _seen.Clear();
                _seenFlush = DateTime.Now;
            }
            _seenDirty = false;
            _blockedDirty = false;
            LastHit = "";
            Interlocked.Exchange(ref Seen, 0);
            Interlocked.Exchange(ref Reinjected, 0);
            Interlocked.Exchange(ref Dropped, 0);
            Interlocked.Exchange(ref NameHits, 0);
        }

        private static readonly Dictionary<string, string> _seen = new Dictionary<string, string>(StringComparer.Ordinal);
        private static DateTime _seenFlush = DateTime.Now;

        // V-31 / V-34: 所有落盘都在这个专用写线程上做，捕获线程只改内存 + 置脏。
        // 这样既不会让 UDP 排队等磁盘，也不会有"两个 FlushSeen 互相覆盖"的竞态。
        private static Thread _writer;
        private static volatile bool _writerStop;
        private static readonly AutoResetEvent _writerSignal = new AutoResetEvent(false);
        private static volatile bool _seenDirty, _blockedDirty;

        private static void WriterLoop()
        {
            while (!_writerStop)
            {
                try { _writerSignal.WaitOne(2000); } catch { }
                if (_writerStop) break;
                if (_seenDirty) { _seenDirty = false; FlushSeen(); }
                if (_blockedDirty) { _blockedDirty = false; FlushBlocked(); }
            }
        }

        /// <summary>记录"本机见过/查过哪些端点"——这就是不再依赖对方日志的端点发现来源。</summary>
        private static void RecordSeen(string ep, string name)
        {
            bool flush = false;
            lock (_seen)
            {
                bool known = _seen.ContainsKey(ep);
                if (known && name.Length == 0) { }
                else if (!known && _seen.Count >= MaxSeen) { SeenDropped++; }
                else
                {
                    _seen[ep] = name;
                    flush = (DateTime.Now - _seenFlush).TotalSeconds >= 5 || _seen.Count >= 20;
                    if (flush) _seenFlush = DateTime.Now;
                }
            }
            if (!flush) return;
            _seenDirty = true;                 // 交给写线程，捕获线程不碰磁盘
            try { _writerSignal.Set(); } catch { }
        }

        /// <summary>把内存里"见过的端点"写盘（只在写线程 / 已停止捕获后调用）。</summary>
        private static void FlushSeen()
        {
            try
            {
                List<string> old = new List<string>();
                if (File.Exists(SeenFile))
                    old = SafeFile.Read(SeenFile).Replace("\r\n", "\n").Split('\n')
                        .Where(x => x.Trim().Length > 0 && !x.TrimStart().StartsWith("#")).ToList();
                var map = new Dictionary<string, string>(StringComparer.Ordinal);
                // 新观测优先入表；容量上限 MaxSeen（含磁盘旧数据），防止文件无限增长。
                lock (_seen) { foreach (var kv in _seen) { if (map.Count >= MaxSeen) break; map[kv.Key] = kv.Value; } _seen.Clear(); }   // V-34: 合并在锁内
                long now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
                long ttl = (long)SeenTtl.TotalSeconds;
                foreach (var l in old)
                {
                    if (map.Count >= MaxSeen) break;
                    var p = l.Split('\t');
                    if (p.Length < 1 || p[0].Trim().Length == 0) continue;
                    var ep = p[0].Trim();
                    if (p.Length > 2)
                    {
                        long ts;
                        if (long.TryParse(p[2], out ts) && ts > 0 && now - ts > ttl) continue;   // TTL：过期端点淘汰
                    }
                    if (map.ContainsKey(ep)) continue;
                    map[ep] = p.Length > 1 ? p[1] : "";
                }
                var sb = new StringBuilder();
                sb.Append("# 内置名字层见过的端点（ip:port <TAB> 服名 <TAB> 最后观测 Unix 秒；服名为空表示只见过查询请求）\r\n");
                sb.Append("# 容量上限 ").Append(MaxSeen).Append(" 条，TTL ").Append((int)SeenTtl.TotalDays).Append(" 天；写盘时自动淘汰。\r\n");
                foreach (var kv in map.OrderBy(k => k.Key, StringComparer.Ordinal))
                    sb.Append(kv.Key).Append('\t').Append(SafeFile.CleanName(kv.Value)).Append('\t').Append(now).Append("\r\n");
                SafeFile.Write(SeenFile, sb.ToString());
            }
            catch { }
        }

        /// <summary>把见过的端点并进"已知端点"集合（供扫描 / 候选 / 待解析闭环用）。</summary>
        public static void CollectSeenEndpoints(HashSet<string> set)
        {
            foreach (var f in new[] { SeenFile, BlockedFile })
            {
                foreach (var l in SafeFile.Read(f).Replace("\r\n", "\n").Split('\n'))
                {
                    if (l.Trim().Length == 0 || l.TrimStart().StartsWith("#")) continue;
                    var p = l.Split('\t');
                    var ep = p[0].Trim();
                    if (Regex.IsMatch(ep, @"^\d+\.\d+\.\d+\.\d+:\d+$")) set.Add(ep);
                }
            }
        }
    }
}
