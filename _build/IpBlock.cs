// ============================================================================
//  IpBlock —— SteamServerFilter 的 IP / 网段拦截组件
//
//  为什么需要它：
//    名字匹配天生可绕过（改名、后端显示名程序读不到）。按 IP 拦不受名字影响：
//    一个 endpoint 被封，它的网络流量会被阻断；Steam 组服列表是否删除对应行
//    取决于 L4D2 的组服/匹配客户端，不能由本层保证。
//
//  为什么不用 Windows 防火墙：
//    本机 Private / Public 防火墙配置是「关闭」状态，防火墙规则根本不被执行
//    （实测：规则建好了，包照样通）。所以改用 WinDivert —— 也就是 SteamServerFilter
//    自己正在用的那套内核层丢包机制（驱动已在本机运行，实测可拦）。
//
//  做法：用 WinDivert 开一个只匹配「目标 IP/网段」的过滤器句柄，收到的包直接丢弃
//        （不 re-inject）。只匹配目标地址，所以对其它流量零影响。
//
//  编译： Roslyn csc.exe /target:winexe /platform:x86 /win32manifest:IpBlock.manifest
//        （必须 x86：本机 WinDivert 原生库是 x86 版）
// ============================================================================

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Drawing;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Windows.Forms;

namespace SteamServerFilterIpBlock
{
    internal sealed class IpEntry
    {
        public string Address = "";
        public string Note = "";
        public override string ToString() { return Address; }
    }

    internal sealed class Candidate
    {
        public string Ip = "";
        public int Events;
        public int Ports;
        public List<string> Names = new List<string>();
        public int Unwanted;
        public string Sample = "";
        public bool IsBlocked;
        internal readonly HashSet<string> _ports = new HashSet<string>(StringComparer.Ordinal);

        public string Verdict
        {
            get
            {
                if (Names.Count == 0) return "未知（日志有记录，抓包没见过名字）";
                if (Unwanted == Names.Count) return "全部命中现规则 → 按 IP 拦最安全";
                if (Unwanted == 0) return "无一名命中现规则 → 建议不拦";
                return string.Format("混合（{0}/{1} 命中）→ 需你判断", Unwanted, Names.Count);
            }
        }
    }

    // ------------------------------------------------------- WinDivert 拦截器
    internal static class Blocker
    {
        private const int LAYER_NETWORK = 0;
        private const int SHUTDOWN_BOTH = 3;

        [DllImport("WinDivert.dll", SetLastError = true)]
        private static extern IntPtr WinDivertOpen(string filter, int layer, short priority, ulong flags);
        [DllImport("WinDivert.dll", SetLastError = true)]
        private static extern bool WinDivertRecv(IntPtr handle, byte[] packet, uint packetLen, out uint readLen, IntPtr addr);
        [DllImport("WinDivert.dll", SetLastError = true)]
        private static extern bool WinDivertSetParam(IntPtr handle, int param, ulong value);
        [DllImport("WinDivert.dll", SetLastError = true)]
        private static extern bool WinDivertShutdown(IntPtr handle, int how);
        [DllImport("WinDivert.dll", SetLastError = true)]
        private static extern bool WinDivertClose(IntPtr handle);
        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern IntPtr LoadLibraryW(string path);

        public static string DllPath = "";
        /// <summary>实际加载的 WinDivert.dll 的 SHA-256（加载前已复核）。</summary>
        public static string DllSha256 = "";
        /// <summary>WinDivert.dll 的固定 SHA-256（随项目 windivert\WinDivert.dll 发布，任何替换都会被拒绝）。</summary>
        internal const string ExpectedDllSha256 = "A321649090C21AAA7529CE5D019D242B1D5F2A2AFF04BC3224DB409641604A83";
        private static string _dllError = "";
        /// <summary>FindDll/哈希校验失败的原因（供 --status 与 Start 报错使用）。</summary>
        public static string DllCheckError { get { return _dllError; } }
        public static long Dropped;
        public static int HandleCount;
        public static string LastError = "";

        private static readonly List<IntPtr> _handles = new List<IntPtr>();
        private static readonly List<Thread> _threads = new List<Thread>();
        private static volatile bool _running;
        private static volatile bool _active, _delegated, _nameOnly, _excludeUdp;

        /// <summary>仅表示本进程有正在接收的 IP 层句柄；委托状态不伪造句柄。</summary>
        public static bool IsRunning { get { return _running && HandleCount > 0; } }
        /// <summary>本次成功 Start 的无句柄委托仍由实际运行的名字层执行；Stop 后立即为 false。</summary>
        public static bool IsDelegated
        {
            get { return _delegated && IsActive; }
        }
        /// <summary>本次 Start 的拦截职责已就绪（IP 句柄或有效委托）；UI 启停/重载、watchdog 用此状态。</summary>
        public static bool IsActive
        {
            get { return IsEffective(_active, _delegated, _nameOnly, _excludeUdp, IsRunning, NameLayer.IsRunning, NameLayer.NameOnlyMode); }
        }
        public static bool ExcludesUdp { get { return _active && _excludeUdp; } }

        internal static bool IsEffective(bool active, bool delegated, bool modeAtStart, bool excludeUdp, bool handles, bool nameRunning, bool currentMode)
        {
            if (!active || modeAtStart != currentMode) return false;
            if (delegated) return nameRunning;
            return handles && (!excludeUdp || nameRunning);
        }

        /// <summary>找 WinDivert.dll：只认程序目录下的两个固定位置，并且必须与发布 SHA-256 一致。
        /// 不再回退 %APPDATA%\WindivertDotnet —— 那是用户可写目录，提权进程从那里加载 DLL 会被 DLL 劫持。</summary>
        public static string FindDll()
        {
            _dllError = "";
            var exeDir = IpEngine.Root;
            var cands = new List<string>
            {
                Path.Combine(exeDir, "WinDivert.dll"),
                Path.Combine(exeDir, "windivert", "WinDivert.dll")
            };
            foreach (var c in cands)
            {
                if (!File.Exists(c)) continue;
                var hash = Sha256File(c);
                if (string.Equals(hash, ExpectedDllSha256, StringComparison.OrdinalIgnoreCase))
                {
                    DllSha256 = hash;
                    return c;
                }
                _dllError = "WinDivert.dll 的 SHA-256 与发布值不匹配（可能被替换）：" + c
                          + "（实际 " + (hash.Length == 0 ? "读取失败" : hash) + "，期望 " + ExpectedDllSha256 + "）";
            }
            if (_dllError.Length == 0)
                _dllError = "找不到 WinDivert.dll（只从程序目录或其 windivert 子目录加载，且必须与发布 SHA-256 一致）";
            return "";
        }

        /// <summary>文件的 SHA-256（大写十六进制）；读不到返回空串。</summary>
        internal static string Sha256File(string path)
        {
            try
            {
                using (var sha = System.Security.Cryptography.SHA256.Create())
                using (var fs = File.OpenRead(path))
                {
                    var hash = sha.ComputeHash(fs);
                    var sb = new StringBuilder(hash.Length * 2);
                    foreach (var b in hash) sb.Append(b.ToString("X2"));
                    return sb.ToString();
                }
            }
            catch { return ""; }
        }

        /// <summary>把 ip_block.txt 的地址转成 WinDivert 过滤表达式（分块，避免过长）。</summary>
        public static List<string> BuildFilters(List<IpEntry> entries, bool excludeUdp = false)
        {
            var parts = new List<string>();
            foreach (var e in entries)
            {
                string endpointIp; int endpointPort;
                if (IpEngine.TryParseEndpoint(e.Address, out endpointIp, out endpointPort))
                {
                    // 委托名字层时 endpoint 没有非 UDP 职责，不能生成 udp and not udp。
                    if (excludeUdp) continue;
                    // 精确 endpoint 规则只拦 IPv4 + UDP 的对应方向端口。
                    parts.Add("(udp and ((ip.DstAddr == " + endpointIp + " and udp.DstPort == " + endpointPort + ") or (ip.SrcAddr == " + endpointIp + " and udp.SrcPort == " + endpointPort + ")))" );
                    continue;
                }
                uint s, t;
                if (!IpEngine.TryParseRange(e.Address, out s, out t)) continue;
                string _addr; List<int> exempt;
                IpEngine.SplitExempt(e.Address, out _addr, out exempt);
                var a = IpEngine.UintToIp(s);
                string ipCond;
                if (s == t) ipCond = "(ip.DstAddr == " + a + " or ip.SrcAddr == " + a + ")";
                else
                {
                    var b = IpEngine.UintToIp(t);
                    ipCond = "((ip.DstAddr >= " + a + " and ip.DstAddr <= " + b + ") or (ip.SrcAddr >= " +
                             a + " and ip.SrcAddr <= " + b + "))";
                }
                if (exempt.Count > 0)
                {
                    // 只对"这个地址 + 这些 UDP 端口"放行；TCP 等其它协议照常拦
                    var ex = new StringBuilder();
                    foreach (var p in exempt)
                    {
                        if (ex.Length > 0) ex.Append(" and ");
                        ex.Append("(udp.DstPort != ").Append(p).Append(" and udp.SrcPort != ").Append(p).Append(")");
                    }
                    ipCond = "(" + ipCond + " and (not udp or (" + ex + ")))";
                }
                parts.Add(ipCond);
            }
            var chunks = new List<string>();
            var cur = new StringBuilder();
            foreach (var p in parts)
            {
                if (cur.Length > 0 && cur.Length + p.Length + 4 > 1500) { chunks.Add(cur.ToString()); cur.Length = 0; }
                if (cur.Length > 0) cur.Append(" or ");
                cur.Append(p);
            }
            if (cur.Length > 0) chunks.Add(cur.ToString());
            // 名字层占用 udp 句柄时，IP 层只抓非 UDP —— 两个句柄过滤器不相交，WinDivert 不会抢包
            if (excludeUdp)
                for (int ci = 0; ci < chunks.Count; ci++) chunks[ci] = "(" + chunks[ci] + ") and not udp";
            return chunks;
        }

        public static string Start(List<IpEntry> entries, bool excludeUdp = false)
        {
            Stop();
            LastError = "";
            Dropped = 0;
            _nameOnly = NameLayer.NameOnlyMode;
            if (_nameOnly)
            {
                // 纯名字 Start 只登记本次委托，不读取/解析 IP 清单，也不加载 IP 层 DLL。
                if (!NameLayer.IsRunning)
                {
                    LastError = "纯名字模式的名字层未运行";
                    return LastError;
                }
                _active = _delegated = true;
                return "OK";
            }
            // 参数保留以兼容调用点；配置意愿不能决定排除 UDP，必须看实际运行状态。
            excludeUdp = IpEngine.ExcludeUdpForNameLayer();
            _excludeUdp = excludeUdp;
            var filters = BuildFilters(entries, excludeUdp);
            if (filters.Count == 0)
            {
                if (excludeUdp && entries.Any(e => IpEngine.IsValidAddress(e.Address)))
                {
                    _active = _delegated = true;
                    return "OK";     // 全 endpoint 已由名字层执行，没有 IP 句柄也是就绪。
                }
                LastError = "清单里没有合法地址";
                return LastError;
            }
            if (DllPath.Length == 0) DllPath = FindDll();
            if (DllPath.Length == 0)
            {
                LastError = DllCheckError.Length > 0 ? DllCheckError : "找不到 WinDivert.dll";
                return LastError;
            }

            // TOCTOU：校验通过后、LoadLibraryW 之前再算一次哈希，防止校验与加载之间文件被替换。
            var full = Path.GetFullPath(DllPath);
            var fullHash = Sha256File(full);
            if (!string.Equals(fullHash, ExpectedDllSha256, StringComparison.OrdinalIgnoreCase))
            {
                LastError = "WinDivert.dll 在加载前哈希复核失败（可能被替换）：" + full
                          + "（实际 " + (fullHash.Length == 0 ? "读取失败" : fullHash) + "，期望 " + ExpectedDllSha256 + "）";
                return LastError;
            }
            DllSha256 = fullHash;
            if (LoadLibraryW(full) == IntPtr.Zero)
            {
                var errCode = Marshal.GetLastWin32Error();
                LastError = "加载 WinDivert.dll 失败: " + full + " (err " + errCode + ")"
                          + (errCode == 193
                              ? ("；位数不匹配 —— 本程序是 " + (Environment.Is64BitProcess ? "x64" : "x86") +
                                 "，请提供对应架构的 WinDivert.dll（x86 子目录）")
                              : "");
                return LastError;
            }

            _running = true;
            foreach (var f in filters)
            {
                var h = WinDivertOpen(f, LAYER_NETWORK, 0, 0);
                if (h == new IntPtr(-1))
                {
                    var err = Marshal.GetLastWin32Error();
                    Stop();
                    LastError = "WinDivertOpen 失败 (err " + err + ")，过滤器: " + f;
                    return LastError;
                }
                try { WinDivertSetParam(h, 0, 16384); } catch { }   // 1.2 队列长度
                try { WinDivertSetParam(h, 1, 8000); } catch { }    // 1.2 队列时间(ms)
                _handles.Add(h);
                var t = new Thread(RecvLoop);
                t.IsBackground = true;
                t.Name = "wd";
                _threads.Add(t);
                t.Start(h);
            }
            _running = true;
            HandleCount = _handles.Count;
            _active = true;
            _delegated = false;
            return "OK";
        }

        private static void RecvLoop(object state)
        {
            var h = (IntPtr)state;
            var buf = new byte[65535];
            var addr = Marshal.AllocHGlobal(64);
            uint read;
            try
            {
                while (_running)
                {
                    // 收到即丢弃（不 re-inject）= 拦截
                    if (WinDivertRecv(h, buf, (uint)buf.Length, out read, addr))
                        Interlocked.Increment(ref Dropped);
                    else if (!_running) break;
                    else Thread.Sleep(1);
                }
            }
            catch { }
            finally { Marshal.FreeHGlobal(addr); }
        }

        public static void Stop()
        {
            _running = false;
            _active = _delegated = _nameOnly = _excludeUdp = false;
            foreach (var h in _handles) { try { WinDivertShutdown(h, SHUTDOWN_BOTH); } catch { } }
            foreach (var h in _handles) { try { WinDivertClose(h); } catch { } }
            foreach (var t in _threads) { try { t.Join(1000); } catch { } }
            _handles.Clear();
            _threads.Clear();
            HandleCount = 0;
        }
    }

    // -------------------------------------------------------------- 业务引擎
    internal static class IpEngine
    {
        public static string Root = AppDomain.CurrentDomain.BaseDirectory;
        public static readonly Encoding Utf8NoBom = new UTF8Encoding(false);

        public const string TaskName = Lifecycle.TaskName;

        public static string IpFile    { get { return Path.Combine(Root, "ip_block.txt"); } }
        public static string RulesFile { get { return Path.Combine(Root, "block_rules.txt"); } }
        public static string LogDir    { get { return Path.Combine(Root, "Logs"); } }
        public static string WireFile  { get { return Path.Combine(Root, "_work", "wire_names.tsv"); } }

        private static readonly TimeSpan RxTimeout = TimeSpan.FromSeconds(2);

        public static string ReadTextShared(string path)
        {
            using (var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite))
            using (var sr = new StreamReader(fs, Encoding.UTF8, true))
                return sr.ReadToEnd();
        }

        private const string Header =
            "# ============================================================\r\n" +
            "# SteamServerFilter IP 拦截清单  ——  由 IpBlock.exe 管理\r\n" +
            "# ============================================================\r\n" +
            "# 每行一条：IP、网段(CIDR) 或精确 IPv4:UDP端口   # 备注\r\n" +
            "#   103.40.13.5        # 無人永生RPG战役 农场\r\n" +
            "#   115.231.235.0/24   # 整个 PURE L4D2 网段\r\n" +
            "# 改完保存即可：IpBlock 在运行时会自动重载（约 5 秒内生效）。\r\n" +
            "# ============================================================\r\n";

        // ---- 地址解析 ----
        public static string UintToIp(uint v)
        {
            return ((v >> 24) & 0xFF) + "." + ((v >> 16) & 0xFF) + "." + ((v >> 8) & 0xFF) + "." + (v & 0xFF);
        }
        /// <summary>手动写入/覆盖 名字→IP 映射（人工认定，绕开自动解析）。</summary>
        public static bool UpsertNameMap(string name, string endpoint)
        {
            var lines = new List<string>();
            if (File.Exists(NameMapFile))
                lines.AddRange(SafeFile.Read(NameMapFile).Replace("\r\n", "\n").Split('\n'));
            bool found = false;
            for (int i = 0; i < lines.Count; i++)
            {
                var l = lines[i];
                if (l.Trim().Length == 0) continue;
                var tab = l.IndexOf('\t');
                if (tab <= 0) continue;
                if (string.Equals(l.Substring(0, tab).Trim(), name, StringComparison.OrdinalIgnoreCase))
                {
                    lines[i] = name + "\t" + endpoint;
                    found = true;
                    break;
                }
            }
            if (!found) lines.Add(name + "\t" + endpoint);
            var sb = new StringBuilder();
            foreach (var l in lines) if (l.Length > 0 || sb.Length > 0) sb.Append(l).Append("\r\n");
            SafeFile.Write(NameMapFile, sb.ToString());   // V-05: 原子写
            return true;
        }

        // ---- 例外端口：地址写成  103.40.13.58!33030  表示"这个地址照拦，但放行 33030 端口" ----
        public static void SplitExempt(string s, out string addr, out List<int> ports)
        {
            ports = new List<int>();
            addr = (s ?? "").Trim();
            var i = addr.IndexOf('!');
            if (i < 0) return;
            var tail = addr.Substring(i + 1);
            addr = addr.Substring(0, i).Trim();
            foreach (var t in tail.Split(new[] { ',', ' ', ';' }, StringSplitOptions.RemoveEmptyEntries))
            {
                int p;
                if (int.TryParse(t.TrimStart('p', 'P', ':'), out p) && p >= 1 && p <= 65535 && !ports.Contains(p))
                    ports.Add(p);
            }
            ports.Sort();
        }

        public static string JoinExempt(string addr, List<int> ports)
        {
            if (ports == null || ports.Count == 0) return addr;
            return addr + "!" + string.Join(",", ports.Select(p => p.ToString()).ToArray());
        }

        public static bool TryParseRange(string s, out uint start, out uint end)
        {
            start = end = 0;
            // 必须在 SplitExempt 之前检查原串，避免 IP!port:port 被吞成整 IP。
            if (string.IsNullOrWhiteSpace(s) || s.Contains(":")) return false;
            string _a; List<int> _p;
            SplitExempt(s, out _a, out _p);
            s = _a;
            string ipPart = s; int prefix = 32;
            if (s.Contains('/'))
            {
                var p = s.Split('/');
                if (p.Length != 2) return false;
                ipPart = p[0];
                if (!int.TryParse(p[1], out prefix) || prefix < 0 || prefix > 32) return false;
            }
            // V-08: .NET 的 IPAddress.TryParse 会把 "103.40.13" 解析成 103.40.0.13，
            // 静默拦错地址；这里先做严格的 4 段点分十进制校验。
            if (!SafeFile.IsStrictIPv4(ipPart)) return false;
            IPAddress a;
            if (!IPAddress.TryParse(ipPart, out a) || a.AddressFamily != AddressFamily.InterNetwork) return false;
            var b = a.GetAddressBytes();
            uint v = ((uint)b[0] << 24) | ((uint)b[1] << 16) | ((uint)b[2] << 8) | b[3];
            if (prefix == 32) { start = end = v; return true; }
            if (prefix == 0) { start = 0; end = 0xFFFFFFFF; return true; }
            uint mask = 0xFFFFFFFF << (32 - prefix);
            start = v & mask;
            end = start | ~mask;
            return true;
        }
        public static bool TryParseEndpoint(string s, out string ip, out int port)
        {
            ip = ""; port = 0;
            if (string.IsNullOrWhiteSpace(s) || s.Contains("!") || s.Contains("/") || s.Count(c => c == ':') != 1) return false;
            var p = s.Trim().Split(':');
            if (p.Length != 2 || !SafeFile.IsStrictIPv4(p[0])) return false;
            if (p[1].Length == 0 || p[1].Any(c => c < '0' || c > '9') ||
                !int.TryParse(p[1], System.Globalization.NumberStyles.None,
                              System.Globalization.CultureInfo.InvariantCulture, out port) ||
                port < 1 || port > 65535) { port = 0; return false; }
            uint a, b;
            if (!TryParseRange(p[0], out a, out b) || a != b) return false;
            ip = p[0];
            return true;
        }

        public static bool IsValidAddress(string s)
        {
            uint a, b;
            return TryParseEndpoint(s, out _, out _) || TryParseRange(s, out a, out b);
        }

        /// <summary>是否是超大网段（/0 等），加入前应二次确认（V-08）。</summary>
        public static bool IsBroadRange(string s, out int prefix, out long hosts)
        {
            prefix = 32; hosts = 1;
            string a1; List<int> p1;
            SplitExempt(s, out a1, out p1);
            var slash = a1.IndexOf('/');
            if (slash < 0) return false;
            int pf;
            if (!int.TryParse(a1.Substring(slash + 1), out pf)) return false;
            prefix = pf;
            hosts = pf <= 0 ? 4294967296L : (1L << (32 - pf));
            return pf <= 8;   // /0~/8 视为超大网段
        }

        /// <summary>两个地址写法是否指同一个基础地址（忽略 !端口 例外）。</summary>
        public static bool SameBaseAddress(string a, string b)
        {
            string ai, bi; int ap, bp;
            bool ae = TryParseEndpoint(a, out ai, out ap), be = TryParseEndpoint(b, out bi, out bp);
            if (ae || be) return ae && be && ai == bi && ap == bp;
            string a1, b1; List<int> p1, p2;
            SplitExempt(a, out a1, out p1);
            SplitExempt(b, out b1, out p2);
            return string.Equals(a1, b1, StringComparison.Ordinal);
        }
        /// <summary>加入或更新一条地址：按"去掉 !端口 后的基础地址"匹配，避免出现重复条目。</summary>
        public static string UpsertEntry(List<IpEntry> entries, string address, string note)
        {
            string endpointIp; int endpointPort;
            if (TryParseEndpoint(address, out endpointIp, out endpointPort))
            {
                int endpointIndex = entries.FindIndex(e => SameBaseAddress(e.Address, address));
                if (endpointIndex >= 0) { if (!string.IsNullOrEmpty(note)) entries[endpointIndex].Note = note; return "updated"; }
                entries.Add(new IpEntry { Address = endpointIp + ":" + endpointPort, Note = note });
                return "added";
            }
            string baseAddr; List<int> ex;
            SplitExempt(address, out baseAddr, out ex);
            int idx = entries.FindIndex(e =>
            {
                string eip; int eport;
                if (TryParseEndpoint(e.Address, out eip, out eport)) return false;
                string a2; List<int> p2;
                SplitExempt(e.Address, out a2, out p2);
                return string.Equals(a2, baseAddr, StringComparison.Ordinal);
            });
            if (idx >= 0)
            {
                // V-02: 只有本次显式带了 !端口 时才改写例外设置；
                // 否则保持原样，避免用不带例外的写法把已设好的"放行端口"冲掉。
                if (ex.Count > 0) entries[idx].Address = address;
                if (!string.IsNullOrEmpty(note)) entries[idx].Note = note;
                return "updated";
            }
            entries.Add(new IpEntry { Address = address, Note = note });
            return "added";
        }

        // ---- 用户态 IP 判定（内置名字层要用：UDP 包在用户态决定丢不丢）----
        private static List<IpEntry> _epCache;
        private static DateTime _epStamp = DateTime.MinValue;

        public static List<IpEntry> EntriesCached()
        {
            DateTime st = DateTime.MinValue;
            try { if (File.Exists(IpFile)) st = File.GetLastWriteTime(IpFile); } catch { }
            if (_epCache == null || st != _epStamp) { _epCache = ReadEntries(); _epStamp = st; }
            return _epCache;
        }

        /// <summary>预解析后的地址区间（V-31：每包路径不再做字符串解析）。</summary>
        public sealed class IpRange { public uint Start, End; public int[] Exempt; public bool Endpoint; public int Port; }

        private static IpRange[] _ranges;
        private static DateTime _rangesStamp = DateTime.MinValue;
        private static DateTime _rangesCheckedAt = DateTime.MinValue;

        /// <summary>让区间缓存失效（自检/切目录后必须调，否则读到旧清单）。</summary>
        public static void InvalidateRangeCache()
        {
            _ranges = null;
            _rangesStamp = DateTime.MinValue;
            _rangesCheckedAt = DateTime.MinValue;
        }

        /// <summary>直接写待解析名单（--reconcile 用）。</summary>
        public static void WritePendingRaw(List<PendingItem> items) { WritePending(items); }

        /// <summary>取预解析区间；文件时间戳最多每秒检查一次（原来每个 UDP 包一次系统调用）。</summary>
        public static IpRange[] ParsedRanges()
        {
            var now = DateTime.Now;
            if (_ranges != null && (now - _rangesCheckedAt).TotalSeconds < 1.0) return _ranges;
            _rangesCheckedAt = now;
            DateTime st = DateTime.MinValue;
            try { if (File.Exists(IpFile)) st = File.GetLastWriteTime(IpFile); } catch { }
            if (_ranges == null || st != _rangesStamp)
            {
                _rangesStamp = st;
                var list = new List<IpRange>();
                foreach (var e in ReadEntries())
                {
                    uint s, t;
                    string endpointIp; int endpointPort;
                    if (TryParseEndpoint(e.Address, out endpointIp, out endpointPort))
                    {
                        TryParseRange(endpointIp, out s, out t);
                        list.Add(new IpRange { Start = s, End = t, Exempt = new int[0], Endpoint = true, Port = endpointPort });
                        continue;
                    }
                    if (!TryParseRange(e.Address, out s, out t)) continue;
                    string a2; List<int> ex;
                    SplitExempt(e.Address, out a2, out ex);
                    list.Add(new IpRange { Start = s, End = t, Exempt = ex.ToArray(), Endpoint = false, Port = 0 });
                }
                _ranges = list.ToArray();
            }
            return _ranges;
        }

        /// <summary>某个 UDP 包是否命中 IP 拦截清单（热路径：全整数比较，无字符串/文件调用）。</summary>
        public static bool IsPacketBlockedFast(string src, int sport, string dst, int dport)
        {
            uint s1, x1, d1, x2;
            if (!TryParseRange(src, out s1, out x1)) return false;
            if (!TryParseRange(dst, out d1, out x2)) return false;
            return IsPacketBlockedFastU(s1, sport, d1, dport);
        }

        /// <summary>热路径版本：调用方已经解析好地址，纯整数比较（V-35）。</summary>
        public static bool IsPacketBlockedFastU(uint s1, int sport, uint d1, int dport)
        {
            var rs = ParsedRanges();
            for (int i = 0; i < rs.Length; i++)
            {
                var r = rs[i];
                bool srcHit = s1 >= r.Start && s1 <= r.End;
                bool dstHit = d1 >= r.Start && d1 <= r.End;
                if (!srcHit && !dstHit) continue;
                if (r.Endpoint) { if ((srcHit && sport == r.Port) || (dstHit && dport == r.Port)) return true; continue; }
                if (r.Exempt.Length == 0) return true;
                bool exempt = false;
                for (int j = 0; j < r.Exempt.Length; j++)
                    if (r.Exempt[j] == sport || r.Exempt[j] == dport) { exempt = true; break; }
                if (exempt) continue;
                return true;
            }
            return false;
        }

        /// <summary>某个 UDP 包是否命中 IP 拦截清单（语义与 WinDivert 表达式一致：
        /// 源或目的地址在清单内，且源/目的端口都没有命中 !例外）。</summary>
        public static bool IsPacketBlocked(string src, int sport, string dst, int dport)
        {
            foreach (var e in EntriesCached())
            {
                string endpointIp; int endpointPort;
                if (TryParseEndpoint(e.Address, out endpointIp, out endpointPort))
                {
                    if ((src == endpointIp && sport == endpointPort) || (dst == endpointIp && dport == endpointPort)) return true;
                    continue;
                }
                uint s, t;
                if (!TryParseRange(e.Address, out s, out t)) continue;
                uint v1, d1, v2, d2;
                bool inSrc = TryParseRange(src, out v1, out d1) && v1 >= s && v1 <= t;
                bool inDst = TryParseRange(dst, out v2, out d2) && v2 >= s && v2 <= t;
                if (!inSrc && !inDst) continue;
                string a2; List<int> ex;
                SplitExempt(e.Address, out a2, out ex);
                if (ex.Count == 0) return true;
                if (ex.Contains(sport) || ex.Contains(dport)) continue;   // 例外端口：放行
                return true;
            }
            return false;
        }

        public static bool ExcludeUdpForNameLayer()
        {
            return NameLayer.IsRunning && !NameLayer.NameOnlyMode;
        }

        public static bool BlockerReady()
        {
            if (Blocker.DllPath.Length == 0) Blocker.DllPath = Blocker.FindDll();
            return Blocker.DllPath.Length > 0;
        }
        public static string BlockerDllPath() { return Blocker.DllPath; }

        // ---- 清单文件 ----
        public static List<IpEntry> ReadEntries()
        {
            var list = new List<IpEntry>();
            if (!File.Exists(IpFile)) return list;
            foreach (var raw in ReadTextShared(IpFile).Replace("\r\n", "\n").Split('\n'))
            {
                var orig = raw;
                var body = orig;
                var h = body.IndexOf('#');
                if (h >= 0) body = body.Substring(0, h);
                body = body.Trim();
                if (body.Length == 0) continue;
                var parts = body.Split(new[] { ' ', '\t' }, StringSplitOptions.RemoveEmptyEntries);
                string note = "";
                var hi = orig.IndexOf('#');
                if (hi >= 0) note = orig.Substring(hi + 1).Trim();
                list.Add(new IpEntry { Address = parts[0], Note = note });
            }
            return list;
        }

        public static void WriteEntries(List<IpEntry> entries)
        {
            var sb = new StringBuilder();
            sb.Append(Header);
            foreach (var e in entries)
            {
                if (string.IsNullOrWhiteSpace(e.Address)) continue;
                // 长地址（带端口放行后缀，如 103.40.13.58!33030,32053）会超过 20 列，
                // PadRight 不再补空白 → 必须自己保证至少一个空格，否则写成 "…,32053# 备注" 解析歧义。
                sb.Append(e.Address.PadRight(20));
                if (e.Address.Length >= 20) sb.Append(' ');
                if (!string.IsNullOrWhiteSpace(e.Note)) sb.Append("# ").Append(e.Note.Trim());
                sb.Append("\r\n");
            }
            SafeFile.Write(IpFile, sb.ToString());   // V-05: 原子替换，避免并发读到写了一半的清单
            // IP 层在名字层模式下把 UDP 委托给名字层；名字层需要立刻看到新增/删除的精确 endpoint。
            try { NameLayer.ReloadIpBlocked(); } catch { }
        }

        public static void EnsureFile() { if (!File.Exists(IpFile)) SafeFile.Write(IpFile, Header); }

        // ---- 证据挖掘 ----
        public static List<string> ReadEngineRules()
        {
            var outp = new List<string>();
            if (!File.Exists(RulesFile)) return outp;
            var text = Encoding.UTF8.GetString(File.ReadAllBytes(RulesFile));
            if (text.Length > 0 && text[0] == '\uFEFF') text = text.Substring(1);
            foreach (var l in text.Replace("\r\n", "\n").Split('\n'))
                if (!string.IsNullOrWhiteSpace(l)) outp.Add(l.Trim());
            return outp;
        }

        private static bool MatchesAny(string name, List<Regex> rules)
        {
            foreach (var r in rules) { try { if (r.IsMatch(name)) return true; } catch { } }
            return false;
        }

        private static List<Candidate> _candCache;
        private static string _candKey = "";

        /// <summary>V-13: 日志目录的"签名"（文件数+总字节+最新写入时间）。
        /// 签名没变就不必把几百 MB 历史日志重扫一遍。</summary>
        private static string FileStamp(string path)
        {
            try { return File.Exists(path) ? File.GetLastWriteTime(path).Ticks.ToString() : "0"; }
            catch { return "x"; }
        }

        /// <summary>1.4：候选列表缓存键 = 日志目录签名 + IP 清单戳 + 规则文件戳。
        /// 三者任一变化才重扫；否则界面每次按钮操作都会重扫 600+ 个日志文件。</summary>
        private static string CandidatesCacheKey()
        {
            return LogsSignature() + "|" + FileStamp(IpFile) + "|" + FileStamp(RulesFile);
        }

        private static string LogsSignature()
        {
            try
            {
                var dir = LogDir;
                if (!Directory.Exists(dir)) return "";
                var files = Directory.GetFiles(dir, "*.log");
                long size = 0, ticks = 0;
                foreach (var f in files)
                {
                    var fi = new FileInfo(f);
                    size += fi.Length;
                    if (fi.LastWriteTime.Ticks > ticks) ticks = fi.LastWriteTime.Ticks;
                }
                return files.Length + "|" + size + "|" + ticks;
            }
            catch { return Guid.NewGuid().ToString(); }
        }
        public static List<Candidate> MineCandidates()
        {
            // V-13: 日志没变化就直接返回上次结果（RefreshAll 每次操作都会调它）
            var key = CandidatesCacheKey();
            if (_candCache != null && key == _candKey) return _candCache;
            var list = MineCandidatesCore();
            _candCache = list;
            _candKey = key;
            return list;
        }

        private static List<Candidate> MineCandidatesCore()
        {
        
            var map = new Dictionary<string, Candidate>(StringComparer.Ordinal);
            Func<string, Candidate> get = ip =>
            {
                Candidate c;
                if (!map.TryGetValue(ip, out c)) { c = new Candidate { Ip = ip }; map[ip] = c; }
                return c;
            };

            var epRx = new Regex(@"(\d+\.\d+\.\d+\.\d+):(\d+)");
            if (Directory.Exists(LogDir))
            {
                // V-13: 只扫最近 40 个日志（历史 600+ 个文件边际价值低、全量 IO 太重）
                var logFiles = Directory.GetFiles(LogDir, "*.log");
                Array.Sort(logFiles, StringComparer.OrdinalIgnoreCase);
                for (int li = Math.Max(0, logFiles.Length - 40); li < logFiles.Length; li++)
                {
                    var f = logFiles[li];
                    string text;
                    try { text = ReadTextShared(f); } catch { continue; }
                    foreach (var line in text.Replace("\r\n", "\n").Split('\n'))
                    {
                        if (line.IndexOf("black list", StringComparison.OrdinalIgnoreCase) < 0 &&
                            line.IndexOf("Block connection to endpoint", StringComparison.Ordinal) < 0) continue;
                        var m = epRx.Match(line);
                        if (!m.Success) continue;
                        var c = get(m.Groups[1].Value);
                        c.Events++;
                        c._ports.Add(m.Groups[2].Value);
                    }
                }
            }

            if (File.Exists(WireFile))
            {
                foreach (var line in ReadTextShared(WireFile).Replace("\r\n", "\n").Split('\n'))
                {
                    if (line.Trim().Length == 0) continue;
                    var tab = line.IndexOf('\t');
                    if (tab < 0) continue;
                    var name = line.Substring(0, tab);
                    var ep = line.Substring(tab + 1).Trim();
                    var colon = ep.LastIndexOf(':');
                    if (colon < 0) continue;
                    var c = get(ep.Substring(0, colon));
                    if (!c.Names.Contains(name)) c.Names.Add(name);
                }
            }

            var rules = new List<Regex>();
            foreach (var r in ReadEngineRules()) { try { rules.Add(new Regex(r, RegexOptions.None, RxTimeout)); } catch { } }
            // V-20: 不能按整串比较（清单里写 103.40.13.58!33030 或 115.231.235.0/24 时，
            // 候选 103.40.13.58 / 115.231.235.64 都应显示"已拦"）；改成区间包含判断。
            var blockedRanges = new List<uint[]>();
            foreach (var e in ReadEntries())
            {
                uint s0, t0;
                // 候选按 IP 聚合：endpoint 不能让整个 IP 显示成已拦。
                string endpointIp; int endpointPort;
                if (TryParseEndpoint(e.Address, out endpointIp, out endpointPort)) continue;
                if (TryParseRange(e.Address, out s0, out t0)) blockedRanges.Add(new[] { s0, t0 });
            }

            var list = map.Values.ToList();
            foreach (var c in list)
            {
                c.Ports = c._ports.Count;
                c.Names.Sort(StringComparer.Ordinal);
                c.Unwanted = c.Names.Count(n => MatchesAny(n, rules));
                c.Sample = c.Names.Count == 0 ? "" : string.Join(" | ", c.Names.Take(3).ToArray());
                uint ipv;
                uint dummy;
                c.IsBlocked = TryParseRange(c.Ip, out ipv, out dummy) &&
                              blockedRanges.Any(r => ipv >= r[0] && ipv <= r[1]);
            }
            list.Sort((a, b) => { int x = b.Events.CompareTo(a.Events); return x != 0 ? x : string.CompareOrdinal(a.Ip, b.Ip); });
            return list;
        }

        // ---- 名字 <-> IP 映射表（让"输入服名"能自动定位到 IP）----
        public static string NameMapFile { get { return Path.Combine(Root, "name_ip_map.tsv"); } }

        public static List<KeyValuePair<string, string>> ReadNameMap()
        {
            var list = new List<KeyValuePair<string, string>>();
            var seen = new HashSet<string>(StringComparer.Ordinal);
            if (!File.Exists(NameMapFile))
            {
                // 首次运行：用之前抓包得到的语料播种，省一次扫描
                var seed = Path.Combine(Root, "_work", "wire_names.tsv");
                if (File.Exists(seed))
                {
                    try
                    {
                        foreach (var l in ReadTextShared(seed).Replace("\r\n", "\n").Split('\n'))
                        {
                            if (l.Trim().Length == 0) continue;
                            var tab = l.IndexOf('\t');
                            if (tab <= 0) continue;
                            MergeNameMap(new[] { new KeyValuePair<string, string>(l.Substring(0, tab), l.Substring(tab + 1).Trim()) });
                        }
                    }
                    catch { }
                }
            }
            if (!File.Exists(NameMapFile)) return list;
            foreach (var l in ReadTextShared(NameMapFile).Replace("\r\n", "\n").Split('\n'))
            {
                if (l.Trim().Length == 0) continue;
                var tab = l.IndexOf('\t');
                if (tab <= 0) continue;
                var k = l.Substring(0, tab) + "\u0001" + l.Substring(tab + 1).Trim();
                if (seen.Add(k)) list.Add(new KeyValuePair<string, string>(l.Substring(0, tab), l.Substring(tab + 1).Trim()));
            }
            return list;
        }

        public static int MergeNameMap(IEnumerable<KeyValuePair<string, string>> entries)
        {
            // V-27: 与 UpsertNameMap / ResolveSmart 一致，用 OrdinalIgnoreCase 折叠大小写，
            // 否则同一服名仅大小写不同会在表里留下两行，解析结果重复。
            var map = new Dictionary<string, HashSet<string>>(StringComparer.OrdinalIgnoreCase);
            if (File.Exists(NameMapFile))
            {
                foreach (var l in ReadTextShared(NameMapFile).Replace("\r\n", "\n").Split('\n'))
                {
                    if (l.Trim().Length == 0) continue;
                    var tab = l.IndexOf('\t');
                    if (tab <= 0) continue;
                    var nm = l.Substring(0, tab);
                    var ep = l.Substring(tab + 1).Trim();
                    HashSet<string> s;
                    if (!map.TryGetValue(nm, out s)) { s = new HashSet<string>(StringComparer.OrdinalIgnoreCase); map[nm] = s; }
                    s.Add(ep);
                }
            }
            int added = 0;
            foreach (var kv in entries)
            {
                var nm = SafeFile.CleanName(kv.Key);   // V-10: 统一清洗（含 BOM / U+FFFD）
                var ep = (kv.Value ?? "").Trim();
                if (nm.Length == 0 || ep.Length == 0) continue;
                HashSet<string> s;
                if (!map.TryGetValue(nm, out s)) { s = new HashSet<string>(StringComparer.OrdinalIgnoreCase); map[nm] = s; }
                if (s.Add(ep)) added++;
            }
            var sb = new StringBuilder();
            foreach (var nm in map.Keys.OrderBy(k => k, StringComparer.Ordinal))
                foreach (var ep in map[nm].OrderBy(e => e, StringComparer.Ordinal))
                    sb.Append(nm).Append('\t').Append(ep).Append("\r\n");
            SafeFile.Write(NameMapFile, sb.ToString());   // V-05: 原子写
            return added;
        }

        /// <summary>汇集"已知的服务器 endpoint"：日志里被拉黑过的 + 名字表里的 + 常见端口。</summary>
        public static List<string> CollectKnownEndpoints()
        {
            var set = new HashSet<string>(StringComparer.Ordinal);
            var epRx = new Regex(@"(\d+\.\d+\.\d+\.\d+):(\d+)");
            var ips = new HashSet<string>(StringComparer.Ordinal);
            if (Directory.Exists(LogDir))
            {
                // V-13: 只扫最近 40 个日志（历史 600+ 个文件边际价值低、全量 IO 太重）
                var logFiles = Directory.GetFiles(LogDir, "*.log");
                Array.Sort(logFiles, StringComparer.OrdinalIgnoreCase);
                for (int li = Math.Max(0, logFiles.Length - 40); li < logFiles.Length; li++)
                {
                    var f = logFiles[li];
                    string text;
                    try { text = ReadTextShared(f); } catch { continue; }
                    foreach (var line in text.Replace("\r\n", "\n").Split('\n'))
                    {
                        if (line.IndexOf("black list", StringComparison.OrdinalIgnoreCase) < 0 &&
                            line.IndexOf("Block connection to endpoint", StringComparison.Ordinal) < 0) continue;
                        foreach (Match m in epRx.Matches(line))
                        {
                            set.Add(m.Groups[1].Value + ":" + m.Groups[2].Value);
                            ips.Add(m.Groups[1].Value);
                        }
                    }
                }
            }
            // 内置名字层自己记录的端点（查询过 / 按名字封掉的）——不再依赖 SteamServerFilter 的日志
            try { NameLayer.CollectSeenEndpoints(set); } catch { }
            foreach (var kv in ReadNameMap()) set.Add(kv.Value);
            foreach (var ip in ips) set.Add(ip + ":27015");   // 常见默认端口，顺带补一发
            var list = set.ToList();
            list.Sort(StringComparer.Ordinal);
            return list;
        }

        private static string QueryName(string ip, int port, int timeoutMs)
        {
            var req = new byte[] { 0xFF, 0xFF, 0xFF, 0xFF }
                .Concat(Encoding.ASCII.GetBytes("TSource Engine Query")).Concat(new byte[] { 0 }).ToArray();
            using (var udp = new UdpClient())
            {
                udp.Client.ReceiveTimeout = timeoutMs;
                udp.Client.SendTimeout = timeoutMs;
                try
                {
                    udp.Connect(ip, port);
                    udp.Send(req, req.Length);
                    var ep = new IPEndPoint(IPAddress.Any, 0);
                    // V-17: 规则/标签多的服回复会超过 MTU，Source 引擎用分片应答
                    // （首部 FF FF FF FF FE，byte5=分片总数, byte6=序号）；这里自动拼包，
                    // 否则这批服永远拿不到名字、进不了名字↔IP 表。
                    var parts = new Dictionary<int, byte[]>();
                    int total = -1;
                    var deadline = DateTime.Now.AddMilliseconds(Math.Max(timeoutMs, 1500));
                    while (DateTime.Now < deadline)
                    {
                        byte[] d;
                        try { d = udp.Receive(ref ep); } catch { break; }
                        if (d.Length > 5 && d[4] == (byte)'A')      // S2C_CHALLENGE
                        {
                            udp.Send(req.Concat(new ArraySegment<byte>(d, 5, 4)).ToArray(), req.Length + 4);
                            continue;
                        }
                        if (d.Length > 7 && d[0] == 0xFF && d[1] == 0xFF && d[2] == 0xFF && d[3] == 0xFF && d[4] == 0xFE)
                        {
                            total = d[5];
                            var idx = d[6];
                            var payload = new byte[d.Length - 7];
                            Array.Copy(d, 7, payload, 0, payload.Length);
                            parts[idx] = payload;
                            if (total > 0 && parts.Count >= total) break;
                            continue;
                        }
                        if (d.Length > 7 && d[4] == (byte)'I')
                        {
                            int e = Array.IndexOf(d, (byte)0, 6);
                            if (e > 6) return Encoding.UTF8.GetString(d, 6, e - 6);
                        }
                        break;
                    }
                    if (total > 0 && parts.Count >= total)
                    {
                        var all = new List<byte>();
                        for (int i = 0; i < total; i++)
                        {
                            byte[] part;
                            if (!parts.TryGetValue(i, out part)) return null;
                            all.AddRange(part);
                        }
                        var joined = all.ToArray();
                        if (joined.Length > 7 && joined[4] == (byte)'I')
                        {
                            int e = Array.IndexOf(joined, (byte)0, 6);
                            if (e > 6) return Encoding.UTF8.GetString(joined, 6, e - 6);
                        }
                    }
                }
                catch { }
            }
            return null;
        }

        public sealed class SweepResult { public int Scanned; public int Found; public int Added; }

        /// <summary>并发扫描已知 endpoint，把所有能拿到名字的服务器写进 名字↔IP 表。</summary>
        public static SweepResult SweepNames(int workers, int timeoutMs, Action<int, int> progress)
        {
            var eps = CollectKnownEndpoints();
            var q = new System.Collections.Concurrent.ConcurrentQueue<string>(eps);
            var hits = new System.Collections.Concurrent.ConcurrentQueue<KeyValuePair<string, string>>();
            int done = 0, found = 0;
            var threads = new List<Thread>();
            for (int i = 0; i < workers; i++)
            {
                var t = new Thread(() =>
                {
                    string ep;
                    while (q.TryDequeue(out ep))
                    {
                        var c = ep.LastIndexOf(':');
                        if (c <= 0) continue;
                        var ip = ep.Substring(0, c);
                        int port;
                        if (!int.TryParse(ep.Substring(c + 1), out port)) continue;
                        var nm = QueryName(ip, port, timeoutMs);
                        if (nm != null && nm.Trim().Length > 0)
                        {
                            Interlocked.Increment(ref found);
                            hits.Enqueue(new KeyValuePair<string, string>(nm, ep));
                        }
                        int d = Interlocked.Increment(ref done);
                        if (progress != null && d % 50 == 0) progress(d, eps.Count);
                    }
                });
                t.IsBackground = true; t.Start(); threads.Add(t);
            }
            foreach (var t in threads) t.Join(600000);
            var res = new SweepResult { Scanned = eps.Count, Found = found };
            res.Added = MergeNameMap(hits.ToList());
            return res;
        }

        private static bool IsCjk(char c)
        {
            return (c >= 0x4E00 && c <= 0x9FFF) || (c >= 0x3400 && c <= 0x4DBF) || (c >= 0xF900 && c <= 0xFAFF);
        }

        /// <summary>把名字切成"关键词"：拉丁/数字一段、中文一段，丢掉纯数字与单字符。</summary>
        private static List<string> Tokenize(string s)
        {
            var outp = new List<string>();
            var cur = new StringBuilder();
            int mode = 0;   // 0 其它, 1 拉丁数字, 2 中文
            Action flush = () =>
            {
                var t = cur.ToString();
                cur.Length = 0;
                if (t.Length < 2) return;
                bool allDigit = true;
                foreach (var ch in t) if (!char.IsDigit(ch)) { allDigit = false; break; }
                if (allDigit) return;
                var low = t.ToLowerInvariant();
                if (!outp.Contains(low)) outp.Add(low);
            };
            foreach (var ch in s)
            {
                int m = IsCjk(ch) ? 2 : (char.IsLetterOrDigit(ch) ? 1 : 0);
                if (m == 0) { flush(); mode = 0; continue; }
                if (mode != 0 && m != mode) flush();
                mode = m;
                cur.Append(ch);
            }
            flush();
            return outp;
        }

        /// <summary>
        /// 智能解析服名 -> IP:端口。
        /// 依次尝试：精确 → 表名含输入 → 输入含表名 → **关键词（品牌 token）匹配**。
        /// 最后一步是关键：浏览器显示的名字（如 "PURE L4D2 10 #8"）和 A2S 里的名字
        /// （"[Pure][10] L4D2"）并不一样，靠共同的关键词 "pure" 才能认出是同一批服。
        /// </summary>
        public static List<KeyValuePair<string, string>> ResolveSmart(string text, out string how)
        {
            how = "";
            var t = (text ?? "").Trim();
            var all = ReadNameMap();
            if (t.Length == 0 || all.Count == 0) return new List<KeyValuePair<string, string>>();

            var hits = all.Where(kv => string.Equals(kv.Key, t, StringComparison.OrdinalIgnoreCase)).ToList();
            if (hits.Count > 0) { how = "精确匹配"; return hits; }

            hits = all.Where(kv => kv.Key.IndexOf(t, StringComparison.OrdinalIgnoreCase) >= 0).ToList();
            if (hits.Count > 0) { how = "名字包含匹配"; return hits; }

            hits = all.Where(kv => kv.Key.Trim().Length >= 3 &&
                                   t.IndexOf(kv.Key, StringComparison.OrdinalIgnoreCase) >= 0).ToList();
            if (hits.Count > 0) { how = "反向包含匹配"; return hits; }

            var qTok = Tokenize(t);
            if (qTok.Count == 0) return new List<KeyValuePair<string, string>>();

            var df = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
            foreach (var kv in all)
                foreach (var tok in Tokenize(kv.Key))
                {
                    int c;
                    df[tok] = df.TryGetValue(tok, out c) ? c + 1 : 1;
                }

            string best = null; int bestDf = int.MaxValue;
            foreach (var tok in qTok)
            {
                int c;
                if (df.TryGetValue(tok, out c) && c < bestDf) { bestDf = c; best = tok; }
            }
            if (best == null)
            {
                how = "映射表里没有含相同关键词的服名（这个服还没被扫描/抓包记录过）";
                return new List<KeyValuePair<string, string>>();
            }
            if (bestDf > 150)
            {
                // 只剩太通用的关键词（例如 "l4d2"），用它去匹配会把一大堆无关服拉进来
                how = "关键词太通用（\"" + best + "\" 出现在 " + bestDf + " 个服名里），不自动解析";
                return new List<KeyValuePair<string, string>>();
            }

            hits = all.Where(kv => Tokenize(kv.Key).Contains(best, StringComparer.OrdinalIgnoreCase)).ToList();
            how = "关键词匹配（\"" + best + "\" 出现在 " + bestDf + " 个服名里，命中 " + hits.Count + " 个）";
            return hits;
        }

        /// <summary>
        /// 解析服名 -> 去重后的 IP 列表（不改文件）。
        /// 关键词兜底时会做"支持度过滤"：只有 1 个服名支持的 IP 多半是无关服
        /// （例如搜 "PLUS L4D2" 时，通用关键词 "l4d2" 会把 "L4D2 Prison" 也拉进来）。
        /// </summary>
        public static List<string> ResolveIps(string text, out string how, out List<string> matchedNames)
        {
            matchedNames = new List<string>();
            var hits = ResolveSmart(text, out how);
            var support = new Dictionary<string, int>(StringComparer.Ordinal);
            var order = new List<string>();
            foreach (var kv in hits)
            {
                if (!matchedNames.Contains(kv.Key)) matchedNames.Add(kv.Key);
                var c = kv.Value.LastIndexOf(':');
                var ip = c > 0 ? kv.Value.Substring(0, c) : kv.Value;
                if (!IsValidAddress(ip)) continue;
                if (!support.ContainsKey(ip)) { support[ip] = 0; order.Add(ip); }
                support[ip]++;
            }
            var ips = new List<string>();
            foreach (var ip in order)
            {
                if (matchedNames.Count > 5 && support[ip] < 2) continue;
                ips.Add(ip);
            }
            return ips;
        }

        /// <summary>
        /// 解析服名 -> 精确 endpoint 列表（不改文件）。
        /// 与 ResolveIps 的 support 过滤一致，但保留端口，供"共享 IP"改成按端口拦截。
        /// </summary>
        public static List<KeyValuePair<string, string>> ResolveEndpoints(string text, out string how, out List<string> matchedNames)
        {
            matchedNames = new List<string>();
            var hits = ResolveSmart(text, out how);
            var support = new Dictionary<string, int>(StringComparer.Ordinal);
            foreach (var kv in hits)
            {
                if (!matchedNames.Contains(kv.Key)) matchedNames.Add(kv.Key);
                string ip; int port;
                if (!TryParseEndpoint(kv.Value, out ip, out port)) continue;
                int c;
                support[ip] = support.TryGetValue(ip, out c) ? c + 1 : 1;
            }
            var accepted = new List<KeyValuePair<string, string>>();
            foreach (var kv in hits)
            {
                string ip; int port;
                if (!TryParseEndpoint(kv.Value, out ip, out port)) continue;
                int c;
                if (matchedNames.Count > 5 && (!support.TryGetValue(ip, out c) || c < 2)) continue;
                accepted.Add(kv);
            }
            return accepted;
        }

        /// <summary>兼容旧接口：在 名字↔IP 表里找匹配项。</summary>
        public static List<KeyValuePair<string, string>> ResolveName(string text)
        {
            string how;
            return ResolveSmart(text, out how);
        }

        // 共享 IP 上最多自动添加多少个精确 endpoint，避免一条宽泛名字生成上千条过滤器。
        public const int MaxAutoEndpoints = 256;

        /// <summary>上一次 AddNameToBlockList 给用户看的说明（共享 IP 改精确拦截等）。</summary>
        public static string LastAddNote = "";

        private sealed class NameIndex
        {
            public readonly Dictionary<string, HashSet<string>> NamesByIp =
                new Dictionary<string, HashSet<string>>(StringComparer.Ordinal);
            public readonly Dictionary<string, List<string>> EndpointsByName =
                new Dictionary<string, List<string>>(StringComparer.OrdinalIgnoreCase);
        }

        /// <summary>从 名字↔IP 表建立两个索引：每个 IP 上有哪些服名、每个服名对应哪些 endpoint。</summary>
        private static NameIndex BuildNameIndex()
        {
            var idx = new NameIndex();
            foreach (var kv in ReadNameMap())
            {
                var name = (kv.Key ?? "").Trim();
                var value = (kv.Value ?? "").Trim();
                if (name.Length == 0 || value.Length == 0) continue;

                string ip; int port;
                string ipKey = null;
                if (TryParseEndpoint(value, out ip, out port))
                {
                    ipKey = ip;
                    List<string> eps;
                    if (!idx.EndpointsByName.TryGetValue(name, out eps))
                    {
                        eps = new List<string>();
                        idx.EndpointsByName[name] = eps;
                    }
                    if (!eps.Contains(value, StringComparer.OrdinalIgnoreCase)) eps.Add(value);
                }
                else if (!value.Contains("!") && !value.Contains("/"))
                {
                    uint a, b;
                    if (TryParseRange(value, out a, out b) && a == b) ipKey = value;
                }
                if (ipKey == null) continue;

                HashSet<string> names;
                if (!idx.NamesByIp.TryGetValue(ipKey, out names))
                {
                    names = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                    idx.NamesByIp[ipKey] = names;
                }
                names.Add(name);
            }
            return idx;
        }

        /// <summary>清单里是否已经有一条会覆盖该 IP 的条目（裸 IP、ip!端口、endpoint 都算）。</summary>
        private static bool EntryTouchesIp(List<IpEntry> entries, string ip)
        {
            foreach (var e in entries)
            {
                string eip; int ep;
                if (TryParseEndpoint(e.Address, out eip, out ep))
                {
                    if (string.Equals(eip, ip, StringComparison.Ordinal)) return true;
                    continue;
                }
                var baseAddr = (e.Address ?? "").Trim();
                var bang = baseAddr.IndexOf('!');
                if (bang >= 0) baseAddr = baseAddr.Substring(0, bang);
                uint a, b;
                if (TryParseRange(baseAddr, out a, out b) && a == b &&
                    string.Equals(UintToIp(a), ip, StringComparison.Ordinal)) return true;
            }
            return false;
        }

        /// <summary>把名字解析成拦截地址并加入清单；返回加入的地址列表。
        /// 如果目标 IP 上还有其它服名（共享 IP），只加精确的 ip:port，避免连坐同 IP 的其它服。
        /// rule 非空时会记下"这条规则带来了哪些地址"，方便删规则时一并释放。</summary>
        public static List<string> AddNameToBlockList(string text, out List<string> matchedNames, string rule = null)
        {
            LastAddNote = "";
            string how;
            var hits = ResolveEndpoints(text, out how, out matchedNames);
            var entries = ReadEntries();
            var added = new List<string>();
            if (hits.Count == 0) return added;

            var idx = BuildNameIndex();
            int endpointBudget = MaxAutoEndpoints;
            int sharedConverted = 0, capped = 0, narrowed = 0;
            foreach (var kv in hits)
            {
                string ip; int port;
                if (!TryParseEndpoint(kv.Value, out ip, out port)) continue;

                HashSet<string> names;
                bool shared = idx.NamesByIp.TryGetValue(ip, out names) && names.Count > 1;
                bool asEndpoint = shared || EntryTouchesIp(entries, ip);
                var address = ip;
                if (asEndpoint)
                {
                    if (endpointBudget <= 0) { capped++; continue; }
                    address = ip + ":" + port;
                    endpointBudget--;
                }
                if (!IsValidAddress(address)) continue;

                // 按"基础地址"判重：同一 endpoint 不能重复加；共享 IP 也不再加裸 IP。
                bool exists = entries.Any(e => SameBaseAddress(e.Address, address));
                if (exists)
                {
                    // V-01: 清单里本来就有这个地址 —— 只记"不引入"的关联（删规则时不会释放它）
                    if (rule != null) AddLink(rule, address, text, false);
                    continue;
                }
                entries.Add(new IpEntry { Address = address, Note = SafeFile.CleanName(text) + "（按名字解析）" });
                added.Add(address);
                if (shared) sharedConverted++;
                else if (asEndpoint) narrowed++;
                if (rule != null) AddLink(rule, address, text, true);    // V-01: 本次真正新增，将来可释放
            }
            if (added.Count > 0) WriteEntries(entries);

            if (sharedConverted > 0)
                LastAddNote = "共享 IP 上有多个服名，已改为按 ip:端口 精确拦截，避免连坐同 IP 的其它服（" + sharedConverted + " 个）。";
            if (capped > 0)
                LastAddNote += (LastAddNote.Length > 0 ? " " : "") +
                               "单次最多添加 " + MaxAutoEndpoints + " 个精确端口，其余未添加。";
            if (narrowed > 0)
                LastAddNote += (LastAddNote.Length > 0 ? " " : "") +
                               "该 IP 已有端口级条目，本次同样按端口拦截，避免扩大范围。";
            return added;
        }

        // ---- 共享 IP 历史数据修复 ----
        /// <summary>上一次 RepairSharedNameBlocks 给用户看的说明。</summary>
        public static string LastRepairNote = "";

        private static bool IsAutoNameNote(string note)
        {
            note = (note ?? "").Trim();
            return note.EndsWith("（按名字解析）", StringComparison.Ordinal);
        }

        private static string AutoNoteName(string note)
        {
            note = (note ?? "").Trim();
            const string suffix = "（按名字解析）";
            return note.EndsWith(suffix, StringComparison.Ordinal)
                ? note.Substring(0, note.Length - suffix.Length).Trim() : note;
        }

        private static bool IsBareExactIp(string address)
        {
            address = (address ?? "").Trim();
            if (address.Length == 0 || address.Contains("!") || address.Contains("/")) return false;
            uint a, b;
            return TryParseRange(address, out a, out b) && a == b;
        }

        /// <summary>
        /// 修复旧版本留下的"按名字解析"裸 IP 条目：如果该 IP 上还有别的服名，
        /// 裸 IP 会把同 IP 的所有服一起拦掉（黑喵/无限火力误拦的根因）。
        /// 改为只保留该名字实际用到的 endpoint，并把名字规则关联迁移过去。
        /// 返回修复的裸 IP 条目数；幂等。
        /// </summary>
        public static int RepairSharedNameBlocks(Action<string> log = null)
        {
            LastRepairNote = "";
            try
            {
                return SafeFile.WithLock(() =>
                {
                    var entries = ReadEntries();
                    var idx = BuildNameIndex();
                    var unsafeEntries = new List<IpEntry>();
                    foreach (var e in entries)
                    {
                        HashSet<string> names;
                        if (IsAutoNameNote(e.Note) && IsBareExactIp(e.Address) &&
                            idx.NamesByIp.TryGetValue(e.Address.Trim(), out names) && names.Count > 1)
                            unsafeEntries.Add(e);
                    }
                    if (unsafeEntries.Count == 0) return 0;

                    var unsafeIps = new HashSet<string>(StringComparer.Ordinal);
                    foreach (var e in unsafeEntries) unsafeIps.Add(e.Address.Trim());

                    var links = ReadLinks();
                    var related = links.Where(l => unsafeIps.Contains((l.Ip ?? "").Trim())).ToList();
                    var keepLinks = links.Where(l => !unsafeIps.Contains((l.Ip ?? "").Trim())).ToList();
                    var newEntries = entries.Where(e => !unsafeEntries.Contains(e)).ToList();

                    int budget = 512;
                    int converted = 0, skipped = 0, capped = 0;
                    foreach (var e in unsafeEntries)
                    {
                        var ip = e.Address.Trim();
                        var names = new List<string>();
                        foreach (var l in related)
                        {
                            if (!string.Equals((l.Ip ?? "").Trim(), ip, StringComparison.Ordinal)) continue;
                            var n = (l.Name ?? "").Trim();
                            if (n.Length > 0 && !names.Contains(n, StringComparer.OrdinalIgnoreCase)) names.Add(n);
                        }
                        var noteName = AutoNoteName(e.Note);
                        if (names.Count == 0 && noteName.Length > 0) names.Add(noteName);

                        // 每个服名只保留它在该 IP 上真实出现的端口，绝不扩大到整个 IP。
                        var perName = new Dictionary<string, List<string>>(StringComparer.OrdinalIgnoreCase);
                        foreach (var n in names)
                        {
                            List<string> eps;
                            if (!idx.EndpointsByName.TryGetValue(n, out eps)) continue;
                            var atIp = new List<string>();
                            foreach (var ep in eps)
                            {
                                string epIp; int epPort;
                                if (!TryParseEndpoint(ep, out epIp, out epPort)) continue;
                                if (!string.Equals(epIp, ip, StringComparison.Ordinal)) continue;
                                if (!atIp.Contains(ep, StringComparer.OrdinalIgnoreCase)) atIp.Add(ep);
                            }
                            if (atIp.Count > 0) perName[n] = atIp;
                        }
                        if (perName.Count == 0) { skipped++; continue; }

                        foreach (var pair in perName)
                        {
                            foreach (var ep in pair.Value)
                            {
                                bool exists = newEntries.Any(x => SameBaseAddress(x.Address, ep));
                                if (!exists)
                                {
                                    if (budget <= 0) { capped++; break; }
                                    newEntries.Add(new IpEntry
                                    {
                                        Address = ep,
                                        Note = SafeFile.CleanName(noteName.Length > 0 ? noteName : pair.Key) + "（按名字解析）"
                                    });
                                    budget--;
                                }
                                converted++;

                                foreach (var l in related)
                                {
                                    if (!string.Equals((l.Ip ?? "").Trim(), ip, StringComparison.Ordinal)) continue;
                                    var ln = (l.Name ?? "").Trim();
                                    bool sameName = string.Equals(ln, pair.Key, StringComparison.OrdinalIgnoreCase);
                                    // 旧数据偶见空服名：只在备注名能对上时迁移，避免把关联乱配。
                                    if (!sameName && ln.Length == 0 &&
                                        string.Equals(pair.Key, noteName, StringComparison.OrdinalIgnoreCase))
                                        sameName = true;
                                    if (!sameName) continue;
                                    keepLinks.Add(new IpLink
                                    {
                                        Rule = l.Rule, Ip = ep, Name = l.Name,
                                        Time = DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss"),
                                        Source = l.Source, Introduced = l.Introduced
                                    });
                                }
                            }
                        }
                    }

                    WriteEntries(newEntries);
                    WriteLinks(keepLinks);
                    LastRepairNote = "已把 " + unsafeEntries.Count + " 条共享 IP 的自动拦截改为精确端口"
                        + (skipped > 0 ? "（" + skipped + " 条缺少端口映射，交回名字层）" : "")
                        + (capped > 0 ? "（端口数超过预算，其余未迁移）" : "") + "。";
                    if (log != null) log(LastRepairNote);
                    return unsafeEntries.Count;
                });
            }
            catch (Exception ex)
            {
                LastRepairNote = "共享 IP 自动拦截修复失败：" + ex.Message;
                if (log != null) log(LastRepairNote);
                return 0;
            }
        }

        // ---- 待解析名单：解析不出 IP 的服名先记下来，等检测到它的 IP 再自动补拦 ----
        public static string PendingFile { get { return Path.Combine(Root, "pending_resolve.tsv"); } }

        public sealed class PendingItem
        {
            public string Name = "";
            public string Added = "";
            public string Rule = "";   // 当时加的那条名字规则（删规则时据此释放 IP）
        }

        public static List<PendingItem> ReadPending()
        {
            var list = new List<PendingItem>();
            if (!File.Exists(PendingFile)) return list;
            foreach (var l in ReadTextShared(PendingFile).Replace("\r\n", "\n").Split('\n'))
            {
                if (l.Trim().Length == 0 || l.TrimStart().StartsWith("#")) continue;
                var p = l.Split('\t');
                list.Add(new PendingItem
                {
                    Name = p[0].Trim(),
                    Added = p.Length > 1 ? p[1].Trim() : "",
                    Rule = p.Length > 2 ? p[2].Trim() : ""
                });
            }
            return list;
        }

        private static void WritePending(List<PendingItem> items)
        {
            var sb = new StringBuilder();
            sb.Append("# 待解析的服名（已用名字规则先拦着，等检测到 IP 后自动补进 IP 拦截清单）\r\n");
            sb.Append("# 服名 <TAB> 加入时间 <TAB> 名字规则\r\n");
            foreach (var it in items)
                sb.Append(it.Name).Append('\t').Append(it.Added).Append('\t').Append(it.Rule).Append("\r\n");
            SafeFile.Write(PendingFile, sb.ToString());   // V-05: 原子写
        }

        /// <summary>按规则名清掉待解析条目（删规则时用）。
        /// 关键：不能只在"该规则有 IP 关联"时才清 —— 那种情况根本没写 pending，
        /// 真正会留孤儿的是"加了规则但没解析出 IP"的条目（实测躺了 3 小时）。</summary>
        public static int RemovePendingByRule(string rule)
        {
            if (string.IsNullOrEmpty(rule)) return 0;
            try
            {
                var list = ReadPending();
                var keep = list.Where(x => !string.Equals(x.Rule, rule, StringComparison.Ordinal)).ToList();
                var n = list.Count - keep.Count;
                if (n > 0) WritePending(keep);
                return n;
            }
            catch { return 0; }
        }

        public static bool AddPending(string name, string rule = null)
        {
            name = SafeFile.CleanName(name);          // V-10: 服名来自 A2S，含 \t/\n 会破坏 TSV
            if (name.Length == 0) return false;
            var list = ReadPending();
            if (list.Any(kv => string.Equals(kv.Name, name, StringComparison.OrdinalIgnoreCase))) return false;
            list.Add(new PendingItem
            {
                Name = name,
                Added = DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss"),
                Rule = SafeFile.Clean(rule ?? name)
            });
            WritePending(list);
            return true;
        }

        public static void RemovePending(string name)
        {
            var list = ReadPending().Where(kv => !string.Equals(kv.Name, name, StringComparison.OrdinalIgnoreCase)).ToList();
            WritePending(list);
        }

        private static DateTime _lastSweep = DateTime.MinValue;

        /// <summary>
        /// 把"待解析"的服名逐个再试：能在 名字↔IP 表里查到就补进 IP 清单并移出待解析。
        /// 都查不到、且距上次扫描超过 sweepIntervalMinutes 分钟时，才做一次扫描
        /// （扫描会主动查询已知 endpoint；过滤器把新服按名字拦下后，它的 IP:端口 会进日志，
        ///   于是下次扫描就能查到它 —— 这就是"检测到再自动补上"的闭环）。
        /// </summary>
        public static int ResolvePending(bool allowSweep, int sweepIntervalMinutes, Action<string> log)
        {
            if (ReadPending().Count == 0) return 0;
            int added = 0;
            Action oneRound = () =>
            {
                foreach (var kv in ReadPending())
                {
                    string how; List<string> names;
                    var ips = ResolveIps(kv.Name, out how, out names);
                    if (ips.Count == 0) continue;
                    var got = AddNameToBlockList(kv.Name, out names, kv.Rule);
                    RemovePending(kv.Name);
                    if (log != null)
                        log("· 待解析服「" + kv.Name + "」已定位（" + how + "）：" +
                            (got.Count > 0 ? ("已加入 IP 清单 " + string.Join(", ", got.ToArray()))
                                           : "对应 IP 已在清单里"));
                    added += got.Count;
                }
            };
            oneRound();
            if (allowSweep && ReadPending().Count > 0 &&
                (DateTime.Now - _lastSweep).TotalMinutes >= sweepIntervalMinutes)
            {
                _lastSweep = DateTime.Now;
                if (log != null) log("· 还有 " + ReadPending().Count + " 个待解析服名，扫描已知服务器来定位它们的 IP ...");
                var res = SweepNames(64, 1200, null);
                if (log != null) log("  扫描完成：endpoint " + res.Scanned + " 个，拿到名字 " + res.Found +
                                     " 个，映射表新增 " + res.Added + " 条。");
                oneRound();
                if (log != null && ReadPending().Count > 0)
                    log("  仍有 " + ReadPending().Count + " 个没定位到（该服还没在本机流量里出现过？）");
            }
            return added;
        }

        // ---- 名字规则 <-> 它带来的 IP 的关联（删名字时据此释放 IP）----
        // 列：规则 \t IP \t 录入服名 \t 时间 \t 来源 \t 本次新增(1/0)
        // V-01：只有"本次真正把该 IP 加进清单"的关联才允许在删规则时释放；
        //       内置规则档（rpg/cn/playmode/…）的规则永不挂关联，删宽泛规则不会拆掉精确 IP 封锁。
        public static string LinkFile { get { return Path.Combine(Root, "name_ip_links.tsv"); } }

        public sealed class IpLink
        {
            public string Rule = "", Ip = "", Name = "", Time = "", Source = "rule";
            public bool Introduced = true;
        }

        public static List<IpLink> ReadLinks()
        {
            var list = new List<IpLink>();
            foreach (var l in SafeFile.Read(LinkFile).Replace("\r\n", "\n").Split('\n'))
            {
                if (l.Trim().Length == 0 || l.TrimStart().StartsWith("#")) continue;
                var p = l.Split('\t');
                if (p.Length < 2) continue;
                list.Add(new IpLink
                {
                    Rule = p[0],
                    Ip = p[1],
                    Name = p.Length > 2 ? p[2] : "",
                    Time = p.Length > 3 ? p[3] : "",
                    Source = (p.Length > 4 && p[4].Trim().Length > 0) ? p[4].Trim() : "rule",
                    Introduced = p.Length <= 5 || p[5].Trim() != "0"
                });
            }
            return list;
        }

        public static void WriteLinks(List<IpLink> links)
        {
            var sb = new StringBuilder();
            sb.Append("# 名字规则 -> 它带来的 IP（删【自定义】名字规则时会一并释放这些 IP）\r\n");
            sb.Append("# 规则 <TAB> IP <TAB> 录入服名 <TAB> 时间 <TAB> 来源(custom/capture) <TAB> 本次新增(1/0)\r\n");
            foreach (var l in links)
                sb.Append(SafeFile.Clean(l.Rule)).Append('\t').Append(SafeFile.Clean(l.Ip)).Append('\t')
                  .Append(SafeFile.CleanName(l.Name)).Append('\t').Append(l.Time).Append('\t')
                  .Append(l.Source == "capture" ? "capture" : "custom").Append('\t')
                  .Append(l.Introduced ? "1" : "0").Append("\r\n");
            SafeFile.Write(LinkFile, sb.ToString());
        }

        /// <summary>上一次 ReleaseIpsForRule 保留 IP 的原因说明（供界面/CLI 显示）。</summary>
        public static string LastReleaseKeptReason = "";

        /// <summary>规则是否来自内置规则档（rpg/cn/playmode/brands/pureplus，不含 custom）。
        /// 内置档多为宽泛正则，删它不应连带拆掉 IP 封锁（审计 V-01）。</summary>
        public static bool RuleInBuiltinProfile(string rule)
        {
            rule = (rule ?? "").Trim();
            if (rule.Length == 0) return false;
            try
            {
                var dir = Path.Combine(Root, "rules-profiles");
                if (!Directory.Exists(dir)) return false;
                foreach (var f in Directory.GetFiles(dir, "*.txt"))
                {
                    if (string.Equals(Path.GetFileName(f), "custom.txt", StringComparison.OrdinalIgnoreCase)) continue;
                    foreach (var l in SafeFile.Read(f).Replace("\r\n", "\n").Split('\n'))
                    {
                        var s = l.Trim();
                        if (s.Length == 0 || s.StartsWith("#")) continue;
                        if (string.Equals(s, rule, StringComparison.Ordinal)) return true;
                    }
                }
            }
            catch { }
            return false;
        }

        /// <summary>记录/更新关联。introduced = 本次是否真的新增了该 IP（决定将来能否释放）。</summary>
        public static void AddLink(string rule, string ip, string name, bool introduced = true, string source = "custom")
        {
            rule = SafeFile.Clean(rule);
            ip = SafeFile.Clean(ip);
            name = SafeFile.CleanName(name);
            if (rule.Length == 0 || ip.Length == 0) return;
            if (RuleInBuiltinProfile(rule)) return;   // V-01: 内置档规则不挂关联
            SafeFile.WithLock(() =>
            {
                var links = ReadLinks();
                foreach (var l in links)
                {
                    if (string.Equals(l.Rule, rule, StringComparison.Ordinal) &&
                        string.Equals(l.Ip, ip, StringComparison.Ordinal))
                    {
                        // 已有关联：只要有一次是"真正新增"，就保留可释放性
                        if (introduced && !l.Introduced) { l.Introduced = true; WriteLinks(links); }
                        return;
                    }
                }
                links.Add(new IpLink
                {
                    Rule = rule, Ip = ip, Name = name, Source = source, Introduced = introduced,
                    Time = DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss")
                });
                WriteLinks(links);
            });
        }

        public static void RemoveLinksForIp(string ip)
        {
            ip = SafeFile.Clean(ip);
            if (ip.Length == 0) return;
            SafeFile.WithLock(() =>
            {
                var links = ReadLinks().Where(l => !string.Equals(l.Ip, ip, StringComparison.Ordinal)).ToList();
                WriteLinks(links);
            });
        }

        /// <summary>
        /// 删掉某条名字规则带来的 IP。仅当以下全部满足才真正释放（审计 V-01 / V-07）：
        ///   · 该规则不在内置档（删宽泛规则不拆 IP 封锁）；
        ///   · 该关联标记为"本次新增"（手动加、候选加的 IP 永不误删）；
        ///   · 没有别的关联还指向这个 IP。
        /// 无论是否释放，都会清掉这条规则的关联记录和对应的待解析条目。
        /// </summary>
        public static List<string> ReleaseIpsForRule(string rule, out List<string> keptIps, out List<string> pendingNames)
        {
            // out 参数不能从 lambda 里赋值，先在锁外用局部变量收集
            var keptLocal = new List<string>();
            var pendLocal = new List<string>();
            var notIntroduced = new List<string>();   // 清单里本来就有、不是这条规则引入的 IP
            var released = SafeFile.WithLock(() =>
            {
                var rel = new List<string>();
                var links = ReadLinks();
                var mine = links.Where(l => string.Equals(l.Rule, rule, StringComparison.Ordinal)).ToList();
                if (mine.Count == 0) return rel;
                foreach (var l in mine) if (l.Name.Length > 0 && !pendLocal.Contains(l.Name)) pendLocal.Add(l.Name);

                var remaining = links.Where(l => !mine.Contains(l)).ToList();
                WriteLinks(remaining);

                if (RuleInBuiltinProfile(rule))
                {
                    keptLocal.AddRange(mine.Select(l => l.Ip).Distinct(StringComparer.Ordinal));
                    return rel;   // 内置档规则：只清理关联，不动 IP
                }

                var releasable = new HashSet<string>(
                    mine.Where(l => l.Introduced).Select(l => l.Ip), StringComparer.Ordinal);
                var stillLinked = new HashSet<string>(remaining.Select(l => l.Ip), StringComparer.Ordinal);

                var entries = ReadEntries();
                foreach (var ip in mine.Select(l => l.Ip).Distinct(StringComparer.Ordinal))
                {
                    if (stillLinked.Contains(ip)) { keptLocal.Add(ip); continue; }   // 还有别的关联要用它
                    if (!releasable.Contains(ip)) { notIntroduced.Add(ip); continue; } // 清单里本来就有，不是这条规则引入的
                    int n = entries.RemoveAll(e => SameBaseAddress(e.Address, ip));
                    if (n > 0) rel.Add(ip); else keptLocal.Add(ip);
                }
                if (rel.Count > 0) WriteEntries(entries);
                return rel;
            });
            keptIps = keptLocal.Distinct(StringComparer.Ordinal).ToList();
            pendingNames = pendLocal.Distinct(StringComparer.Ordinal).ToList();
            LastReleaseKeptReason = notIntroduced.Count > 0
                ? ("其中 " + notIntroduced.Count + " 个是清单里本来就有的 IP（不是这条规则引入的，按设计不释放）")
                : "";
            return released;
        }

        // ---- 验证 / 自启 ----
        public static string VerifyEndpoint(string ip, int port)
        {
            var req = new byte[] { 0xFF, 0xFF, 0xFF, 0xFF }
                .Concat(Encoding.ASCII.GetBytes("TSource Engine Query")).Concat(new byte[] { 0 }).ToArray();
            using (var udp = new UdpClient())
            {
                udp.Client.ReceiveTimeout = 2500;
                udp.Client.SendTimeout = 2500;
                try { udp.Connect(ip, port); udp.Send(req, req.Length); }
                catch (Exception ex) { return "发送失败: " + ex.Message; }
                var ep = new IPEndPoint(IPAddress.Any, 0);
                try
                {
                    var data = udp.Receive(ref ep);
                    string nm = "";
                    if (data.Length > 6 && data[4] == (byte)'I')
                    {
                        int e = Array.IndexOf(data, (byte)0, 6);
                        if (e > 6) nm = Encoding.UTF8.GetString(data, 6, e - 6);
                    }
                    return "仍能收到应答 => 未被拦（名字: " + nm + "）";
                }
                catch (SocketException) { return "无应答（超时）=> 已被拦 / 或该服离线"; }
                catch (Exception ex) { return "异常: " + ex.Message; }
            }
        }

        private static string Run(string file, string args)
        {
            try
            {
                var psi = new ProcessStartInfo(file, args)
                {
                    UseShellExecute = false,
                    CreateNoWindow = true,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    StandardOutputEncoding = Encoding.GetEncoding(936),
                    StandardErrorEncoding = Encoding.GetEncoding(936)
                };
                using (var p = Process.Start(psi))
                {
                    // V-24: 先读 stdout 再读 stderr 会在子进程写满 stderr 时互等死锁；
                    // 改成异步收流，两路都持续被读走。
                    var ob = new StringBuilder();
                    var eb = new StringBuilder();
                    p.OutputDataReceived += (s, e) => { if (e.Data != null) ob.AppendLine(e.Data); };
                    p.ErrorDataReceived += (s, e) => { if (e.Data != null) eb.AppendLine(e.Data); };
                    p.BeginOutputReadLine();
                    p.BeginErrorReadLine();
                    if (!p.WaitForExit(20000)) { try { p.Kill(); } catch { } return "TIMEOUT"; }
                    p.WaitForExit();
                    var o = ob.ToString().Trim();
                    if (p.ExitCode != 0 && o.Length == 0) o = eb.ToString().Trim();
                    return p.ExitCode == 0 ? "OK" : ("FAIL(" + p.ExitCode + ") " + o);
                }
            }
            catch (Exception ex) { return "ERROR: " + ex.Message; }
        }

        public static bool AutostartInstalled()
        {
            return Run("schtasks.exe", "/Query /TN \"" + TaskName + "\"").StartsWith("OK");
        }

        public static string InstallAutostart()
        {
            // 缺口A：schtasks /Create 无法设置"失败自动重启"，改用 XML 注册（RestartOnFailure 1 分钟 × 3 次）。
            string exe = null;
            try { exe = System.Windows.Forms.Application.ExecutablePath; } catch { }
            if (string.IsNullOrEmpty(exe) || !File.Exists(exe)) exe = Path.Combine(Root, "IpBlock.exe");
            Func<string, string> x = s => (s ?? "").Replace("&", "&amp;").Replace("<", "&lt;").Replace(">", "&gt;");
            var user = Environment.UserDomainName + "\\" + Environment.UserName;
            var sb = new StringBuilder();
            sb.AppendLine("<?xml version=\"1.0\" encoding=\"UTF-16\"?>");
            sb.AppendLine("<Task version=\"1.2\" xmlns=\"http://schemas.microsoft.com/windows/2004/02/mit/task\">");
            sb.AppendLine("  <RegistrationInfo><Description>SteamServerFilter: IP + name layer (resident)</Description></RegistrationInfo>");
            sb.AppendLine("  <Triggers><LogonTrigger><Enabled>true</Enabled><UserId>" + x(user) + "</UserId></LogonTrigger></Triggers>");
            sb.AppendLine("  <Principals><Principal id=\"Author\"><UserId>" + x(user) + "</UserId><LogonType>InteractiveToken</LogonType><RunLevel>HighestAvailable</RunLevel></Principal></Principals>");
            sb.AppendLine("  <Settings>");
            sb.AppendLine("    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>");
            sb.AppendLine("    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>");
            sb.AppendLine("    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>");
            sb.AppendLine("    <AllowHardTerminate>true</AllowHardTerminate>");
            sb.AppendLine("    <StartWhenAvailable>true</StartWhenAvailable>");
            sb.AppendLine("    <RestartOnFailure><Interval>PT1M</Interval><Count>3</Count></RestartOnFailure>");
            sb.AppendLine("    <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>");
            sb.AppendLine("    <Enabled>true</Enabled>");
            sb.AppendLine("  </Settings>");
            sb.AppendLine("  <Actions Context=\"Author\"><Exec><Command>" + x(exe) + "</Command><Arguments>--run</Arguments><WorkingDirectory>" + x(Root) + "</WorkingDirectory></Exec></Actions>");
            sb.AppendLine("</Task>");
            var f = Path.Combine(Root, "autostart-task.xml");
            SafeFile.Write(f, sb.ToString());
            var r = Run("schtasks.exe", "/Create /TN \"" + TaskName + "\" /XML \"" + f + "\" /F");
            return r;
        }
public static string RemoveAutostart()
        {
            return Run("schtasks.exe", "/Delete /TN \"" + TaskName + "\" /F");
        }

        public static string HeartbeatFile { get { return Path.Combine(Root, "ip_block.heartbeat.txt"); } }

        // ---- 日志清理（每 3 天由计划任务自动执行）----
        public static string LogRetentionFile { get { return Path.Combine(Root, "log_retention.txt"); } }
        public const string LogTaskName = Lifecycle.LogTaskName;

        /// <summary>保留多少天的日志（默认 30 天）。文件里写一个整数即可改。</summary>
        public static int LogRetentionDays
        {
            get
            {
                var ck = Config.GetInt("log-keep");        // 3.2：config.ini 优先
                if (ck.HasValue) return Math.Max(1, ck.Value);
                try
                {
                    if (File.Exists(LogRetentionFile))
                    {
                        int d;
                        if (int.TryParse(SafeFile.Read(LogRetentionFile).Trim(), out d) && d >= 1 && d <= 3650) return d;
                    }
                }
                catch { }
                return 30;
            }
            set
            {
                var v = value < 1 ? 1 : (value > 3650 ? 3650 : value);
                SafeFile.Write(LogRetentionFile,
                    v + "\r\n# 日志保留天数（FilterTool.exe --logs-prune 用；计划任务每 3 天跑一次）\r\n");
                try { Config.Set("log-keep", v.ToString()); } catch { }   // 3.2
            }
        }

        public sealed class PruneResult
        {
            public int Deleted, Kept;
            public long BytesFreed;
            public List<string> Examples = new List<string>();
        }

        /// <summary>
        /// 删除超过保留期的日志。只认 Logs 目录下的 *.log；今天的日志永不删除；
        /// 非日志文件一律不动（审计 V-18/V-13：日志只增不减）。
        /// </summary>
        public static PruneResult PruneLogs(int keepDays, Action<string> log)
        {
            var res = new PruneResult();
            if (keepDays < 1) keepDays = 1;
            var dir = LogDir;
            if (!Directory.Exists(dir))
            {
                if (log != null) log("· 没有 Logs 目录，无需清理。");
                return res;
            }
            var cutoff = DateTime.Today.AddDays(-keepDays);
            var today = DateTime.Today;
            foreach (var f in Directory.GetFiles(dir, "*.log"))
            {
                DateTime when;
                try
                {
                    var fi = new FileInfo(f);
                    // 用「文件名里的日期」优先（yyyy-MM-dd.log），拿不到再看写入时间
                    var name = Path.GetFileNameWithoutExtension(f);
                    if (!DateTime.TryParseExact(name, "yyyy-MM-dd", null,
                            System.Globalization.DateTimeStyles.None, out when))
                        when = fi.LastWriteTime.Date;
                    if (when >= today) { res.Kept++; continue; }        // 今天的绝不删
                    if (when >= cutoff) { res.Kept++; continue; }
                    var size = fi.Length;
                    File.Delete(f);
                    res.Deleted++;
                    res.BytesFreed += size;
                    if (res.Examples.Count < 5) res.Examples.Add(Path.GetFileName(f));
                }
                catch { res.Kept++; }
            }
            try
            {
                var note = DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss") + "  清理完成：删除 " + res.Deleted +
                           " 个，保留 " + res.Kept + " 个，释放 " + (res.BytesFreed / 1024) + " KB（保留 " + keepDays + " 天）";
                File.AppendAllText(Path.Combine(Root, "logs_prune.log"), note + "\r\n", new UTF8Encoding(false));
            }
            catch { }
            if (log != null)
                log("· 清理完成：删除 " + res.Deleted + " 个，保留 " + res.Kept + " 个，释放 " +
                    (res.BytesFreed / 1024) + " KB（保留 " + keepDays + " 天）");
            return res;
        }

        public static bool LogTaskInstalled()
        {
            return Run("schtasks.exe", "/Query /TN \"" + LogTaskName + "\"").StartsWith("OK");
        }

        /// <summary>安装"每 3 天清理一次日志"的计划任务。</summary>
        public static string InstallLogTask(int keepDays)
        {
            string exe;
            try { exe = Application.ExecutablePath; }
            catch { exe = Path.Combine(Root, "FilterTool.exe"); }
            if (string.IsNullOrEmpty(exe) || !File.Exists(exe)) exe = Path.Combine(Root, "FilterTool.exe");
            var tr = "\"" + exe + "\" --logs-prune " + keepDays;
            return Run("schtasks.exe", "/Create /TN \"" + LogTaskName + "\" /TR \"" + tr +
                                       "\" /SC DAILY /MO 3 /RL HIGHEST /F");
        }

        public static string RemoveLogTask()
        {
            return Run("schtasks.exe", "/Delete /TN \"" + LogTaskName + "\" /F");
        }
        /// <summary>常驻拦截进程定期写心跳，便于 --status / 界面观察真实运行状态。</summary>
        public static void WriteHeartbeat() { WriteHeartbeat(Blocker.IsActive, ""); }

        /// <summary>V-03: 心跳里显式记录"是否真的在丢包"（blocking）与错误状态（state），
        /// 否则重载失败后拦截已停、心跳还在刷新，界面会误报"拦截中"。</summary>
        public static void WriteHeartbeat(bool blocking, string state)
        {
            try
            {
                var p = Process.GetCurrentProcess();
                var sb = new StringBuilder();
                sb.AppendLine("pid=" + p.Id);
                sb.AppendLine("started=" + p.StartTime.ToString("yyyy-MM-dd HH:mm:ss"));
                sb.AppendLine("entries=" + ParsedRanges().Length);   // 1.3：不再每秒整读 ip_block.txt
                sb.AppendLine("handles=" + Blocker.HandleCount);
                sb.AppendLine("dropped=" + Interlocked.Read(ref Blocker.Dropped));
                sb.AppendLine("blocking=" + (blocking ? "yes" : "no"));
                sb.AppendLine("state=" + (state ?? ""));
                sb.AppendLine("build=" + BuildStamp.Time);            // 0.3 版本戳
                sb.AppendLine("namelayer=" + (NameLayer.IsRunning ? "yes" : "no"));
                sb.AppendLine("blockmode=" + (NameLayer.NameOnlyMode ? "name" : "both"));
                sb.AppendLine("namehits=" + Interlocked.Read(ref NameLayer.NameHits));
                sb.AppendLine("nameblocked=" + NameLayer.BlockedCount);
                sb.AppendLine("nameseen=" + Interlocked.Read(ref NameLayer.Seen));
                sb.AppendLine("updated=" + DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss"));
                SafeFile.Write(HeartbeatFile, sb.ToString());
            }
            catch { }
        }

        public static void ClearHeartbeat()
        {
            try { if (File.Exists(HeartbeatFile)) File.Delete(HeartbeatFile); } catch { }
        }

        /// <summary>读取心跳原始字段（V-03：用 TryParseExact 固定格式，避免随系统区域解释出错）。</summary>
        private static Dictionary<string, string> ReadHeartbeatRaw(out bool fresh)
        {
            fresh = false;
            var d = new Dictionary<string, string>(StringComparer.Ordinal);
            var txt = SafeFile.Read(HeartbeatFile);
            if (txt.Length == 0) return null;
            foreach (var l in txt.Replace("\r\n", "\n").Split('\n'))
            {
                var i = l.IndexOf('=');
                if (i > 0) d[l.Substring(0, i).Trim()] = l.Substring(i + 1).Trim();
            }
            DateTime upd;
            if (d.ContainsKey("updated") &&
                DateTime.TryParseExact(d["updated"], "yyyy-MM-dd HH:mm:ss", null,
                    System.Globalization.DateTimeStyles.None, out upd))
                fresh = (DateTime.Now - upd).TotalSeconds < 15;
            return d;
        }

        /// <summary>读取常驻进程心跳；超过 15 秒视为不在运行。</summary>
        public static string ReadHeartbeat(out bool fresh)
        {
            fresh = false;
            try
            {
                var d = ReadHeartbeatRaw(out fresh);
                if (d == null) return null;
                foreach (var k in new[] { "pid", "entries", "handles", "dropped", "updated", "blocking", "state",
                                          "namelayer", "namehits", "nameblocked", "nameseen", "blockmode", "build" })
                    if (!d.ContainsKey(k)) d[k] = "";
                return string.Format("PID {0}，覆盖 {1} 条地址，句柄 {2}，已丢弃 {3} 个包，心跳 {4}{5}",
                    d["pid"], d["entries"], d["handles"], d["dropped"], d["updated"],
                    (d["blocking"] == "no" ? "，★实际未在丢包" + (d["state"].Length > 0 ? "(" + d["state"] + ")" : "") : ""));
            }
            catch { return null; }
        }

        /// <summary>读心跳字段；为空时给个占位（界面显示用）。</summary>
        public static string HeartbeatFieldOr(string key)
        {
            var v = HeartbeatField(key);
            if (v.Length > 0) return v;
            if (key == "nameblocked") return NameLayer.BlockedCount.ToString();
            if (key == "namehits") return Interlocked.Read(ref NameLayer.NameHits).ToString();
            if (key == "nameseen") return Interlocked.Read(ref NameLayer.Seen).ToString();
            return "0";
        }

        /// <summary>读心跳里的某个字段（没有则返回 ""）。</summary>
        public static string HeartbeatField(string key)
        {
            try
            {
                bool fresh;
                var d = ReadHeartbeatRaw(out fresh);
                if (d == null) return "";
                string v;
                return d.TryGetValue(key, out v) ? v : "";
            }
            catch { return ""; }
        }

        /// <summary>V-03: 心跳里的"是否真在丢包"标记（老版本心跳没有该字段时退回 fresh）。</summary>
        public static bool HeartbeatBlocking(out bool fresh, out string state)
        {
            state = "";
            var d = ReadHeartbeatRaw(out fresh);
            if (d == null) return false;
            if (d.ContainsKey("state")) state = d["state"];
            if (!d.ContainsKey("blocking")) return fresh;   // 老格式：只能按心跳新鲜度推断
            return d["blocking"] == "yes";
        }

        /// <summary>心跳里记录的常驻进程 PID（真正在跑 --run 的那个），拿不到返回 0。</summary>
        public static int ResidentPid()
        {
            try
            {
                if (!File.Exists(HeartbeatFile)) return 0;
                foreach (var l in File.ReadAllText(HeartbeatFile, Utf8NoBom).Replace("\r\n", "\n").Split('\n'))
                {
                    if (!l.StartsWith("pid=", StringComparison.Ordinal)) continue;
                    int pid;
                    if (int.TryParse(l.Substring(4).Trim(), out pid)) return pid;
                }
            }
            catch { }
            return 0;
        }

        /// <summary>常驻拦截进程对象（只认心跳里那个 PID，不会把界面窗口误当成它）。</summary>
        public static Process ResidentInstance()
        {
            bool fresh;
            ReadHeartbeat(out fresh);
            if (!fresh) return null;
            var pid = ResidentPid();
            if (pid <= 0 || pid == Process.GetCurrentProcess().Id) return null;
            try { return Process.GetProcessById(pid); } catch { return null; }
        }

        public static string StatusText()
        {
            var e = ReadEntries();
            var sb = new StringBuilder();
            sb.AppendLine("清单: " + e.Count + " 条地址");

            bool fresh;
            var hb = ReadHeartbeat(out fresh);
            string hbState;
            var hbBlocking = HeartbeatBlocking(out fresh, out hbState);
            bool selfRunning = Blocker.IsActive;
            if (selfRunning)
                sb.AppendLine("拦截: 运行中（本进程，句柄 " + Blocker.HandleCount + "，已丢弃 " +
                              Interlocked.Read(ref Blocker.Dropped) + " 个包）");
            else if (NameLayer.NameOnlyMode && HeartbeatField("namelayer") == "yes")
                sb.AppendLine("拦截: 纯名字模式运行中（不使用 ip_block.txt；由内置名字层按服名丢包）");
            else if (fresh && hbBlocking)
                sb.AppendLine("拦截: 运行中（常驻进程 " + hb + "）");
            else if (fresh)
                sb.AppendLine("拦截: ★未生效★（常驻进程 PID " + ResidentPid() + " 活着，但内核句柄已失效 —— 见下方 state）");
            else
                sb.AppendLine("拦截: 未运行" + (hb != null ? "（心跳已过期：" + hb + "）" : ""));

            sb.Append("WinDivert: ");
            if (Blocker.DllPath.Length == 0) Blocker.DllPath = Blocker.FindDll();
            if (Blocker.DllPath.Length == 0)
            {
                sb.Append("未找到！");
                if (Blocker.DllCheckError.Length > 0) sb.Append("（" + Blocker.DllCheckError + "）");
            }
            else
            {
                sb.Append(Blocker.DllPath);
                if (Blocker.DllSha256.Length == 0) Blocker.DllSha256 = Blocker.Sha256File(Blocker.DllPath);
                sb.Append("  [SHA-256 已验证 " + Blocker.DllSha256 + "]");
            }
            sb.AppendLine();
            sb.Append("开机自启: " + (AutostartInstalled() ? "已安装" : "未安装"));
            sb.AppendLine();
            sb.Append("拦截模式: " + NameLayer.ModeName);
            sb.AppendLine();
            sb.Append("名字层(自建): ");
            // 注意：--status 是独立进程，自己没跑名字层；要看常驻进程的状态得读心跳里的字段
            bool hbFresh2; string hbState2;
            var hbBlocking2 = HeartbeatBlocking(out hbFresh2, out hbState2);
            if (!NameLayer.IsRunning && hbFresh2 && HeartbeatField("namelayer") == "yes")
            {
                sb.Append("运行中（常驻进程）· 规则 " + SteamServerFilterRules.Engine.ReadEngineRules().Count +
                          " 条 · 已封端点 " + HeartbeatField("nameblocked") +
                          " · 命中 " + HeartbeatField("namehits") +
                          " · 收 " + HeartbeatField("nameseen"));
                return sb.ToString();
            }
            if (NameLayer.IsRunning)
                sb.Append("运行中 · 规则 " + SteamServerFilterRules.Engine.ReadEngineRules().Count +
                          " 条 · 已封端点 " + NameLayer.BlockedCount +
                          " · 命中 " + Interlocked.Read(ref NameLayer.NameHits) +
                          " · 收 " + Interlocked.Read(ref NameLayer.Seen) +
                          " 重注入 " + Interlocked.Read(ref NameLayer.Reinjected));
            else if (NameLayer.Enabled) sb.Append("已启用但未运行（" + NameLayer.LastError + "）");
            else sb.Append("关闭");
            return sb.ToString();
        }

        /// <summary>读当前"活跃"的拦截进程（含合并版 FilterTool.exe，排除自己）。</summary>
        public static Process[] OtherInstances()
        {
            var me = Process.GetCurrentProcess();
            var names = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { me.ProcessName, "IpBlock", "FilterTool" };
            var list = new List<Process>();
            foreach (var n in names)
            {
                try { list.AddRange(Process.GetProcessesByName(n)); } catch { }
            }
            var seen = new HashSet<int>();
            var outp = new List<Process>();
            foreach (var p in list)
            {
                if (p.Id == me.Id) continue;
                if (!seen.Add(p.Id)) continue;
                outp.Add(p);
            }
            return outp.ToArray();
        }
    }

    // ------------------------------------------------------------------ 界面
    internal sealed class MainForm : Form
    {
        private readonly ListView _lvCand = new ListView();
        private readonly ListView _lvBlocked = new ListView();
        private readonly Button _btnBlockSel = new Button();
        private readonly Button _btnRefresh = new Button();
        private readonly Button _btnUnblock = new Button();
        private readonly Button _btnClearAll = new Button();
        private readonly TextBox _txtIp = new TextBox();
        private readonly TextBox _txtNote = new TextBox();
        private readonly Button _btnAdd = new Button();
        private readonly TextBox _txtName = new TextBox();
        private readonly Button _btnAddName = new Button();
        private readonly Button _btnScan = new Button();
        private readonly Label _lblHint = new Label();
        private readonly Label _lblFw = new Label();
        private readonly Button _btnToggle = new Button();
        private readonly CheckBox _chkAutostart = new CheckBox();
        private readonly TextBox _txtLog = new TextBox();
        private readonly System.Windows.Forms.Timer _timer = new System.Windows.Forms.Timer();

        private List<Candidate> _cands = new List<Candidate>();
        private DateTime _ipFileStamp = DateTime.MinValue;

        private static Font UiFont(float size, FontStyle style)
        {
            string[] names = { "Microsoft YaHei UI", "Microsoft YaHei", "MS Shell Dlg 2" };
            foreach (var n in names) { try { return new Font(n, size, style); } catch { } }
            return new Font(SystemFonts.MessageBoxFont.FontFamily, size, style);
        }

        public MainForm()
        {
            Text = "SteamServerFilter IP 拦截（WinDivert 内核层按 IP / 网段丢包）";
            ClientSize = new Size(900, 752);
            StartPosition = FormStartPosition.CenterScreen;
            FormBorderStyle = FormBorderStyle.FixedSingle;
            MaximizeBox = false;
            Font = UiFont(9f, FontStyle.Regular);
            try { Icon = Icon.ExtractAssociatedIcon(Application.ExecutablePath); } catch { }

            var g1 = new GroupBox();
            g1.Text = "① 已知服务器 IP（证据：Logs 拉黑次数 + 抓包真实服名）";
            g1.Location = new Point(12, 10); g1.Size = new Size(436, 540);
            Controls.Add(g1);
            _lvCand.Location = new Point(14, 22); _lvCand.Size = new Size(408, 440);
            _lvCand.View = View.Details; _lvCand.FullRowSelect = true; _lvCand.GridLines = true;
            _lvCand.MultiSelect = true; _lvCand.HideSelection = false; _lvCand.Font = UiFont(9f, FontStyle.Regular);
            _lvCand.Columns.Add("IP", 110); _lvCand.Columns.Add("拉黑次数", 70);
            _lvCand.Columns.Add("服名数", 60); _lvCand.Columns.Add("已知服名示例", 150);
            g1.Controls.Add(_lvCand);
            _btnBlockSel.Text = "拦截选中 IP";
            _btnBlockSel.Location = new Point(14, 470); _btnBlockSel.Size = new Size(196, 34);
            _btnBlockSel.Font = UiFont(10f, FontStyle.Bold);
            _btnBlockSel.Click += (s, e) => BlockSelected();
            g1.Controls.Add(_btnBlockSel);
            _btnRefresh.Text = "刷新候选";
            _btnRefresh.Location = new Point(220, 470); _btnRefresh.Size = new Size(202, 34);
            _btnRefresh.Click += (s, e) => RefreshAll();
            g1.Controls.Add(_btnRefresh);

            var g2 = new GroupBox();
            g2.Text = "② 拦截清单（ip_block.txt，运行中改文件 5 秒内自动生效）";
            g2.Location = new Point(456, 10); g2.Size = new Size(432, 290);
            Controls.Add(g2);
            _lvBlocked.Location = new Point(14, 22); _lvBlocked.Size = new Size(404, 150);
            _lvBlocked.View = View.Details; _lvBlocked.FullRowSelect = true; _lvBlocked.GridLines = true;
            _lvBlocked.MultiSelect = true; _lvBlocked.HideSelection = false; _lvBlocked.Font = UiFont(9f, FontStyle.Regular);
            _lvBlocked.Columns.Add("IP / 网段", 150); _lvBlocked.Columns.Add("备注", 250);
            g2.Controls.Add(_lvBlocked);
            _btnUnblock.Text = "解除选中";
            _btnUnblock.Location = new Point(14, 180); _btnUnblock.Size = new Size(196, 30);
            _btnUnblock.Click += (s, e) => UnblockSelected();
            g2.Controls.Add(_btnUnblock);
            _btnClearAll.Text = "全部解除";
            _btnClearAll.Location = new Point(220, 180); _btnClearAll.Size = new Size(198, 30);
            _btnClearAll.Click += (s, e) => ClearAll();
            g2.Controls.Add(_btnClearAll);
            _lblFw.Location = new Point(14, 216); _lblFw.Size = new Size(404, 20);
            g2.Controls.Add(_lblFw);
            _btnToggle.Text = "启动拦截";
            _btnToggle.Location = new Point(14, 240); _btnToggle.Size = new Size(196, 30);
            _btnToggle.Font = UiFont(10f, FontStyle.Bold);
            _btnToggle.Click += (s, e) => ToggleBlocking();
            g2.Controls.Add(_btnToggle);
            _chkAutostart.Text = "开机自动启动拦截";
            _chkAutostart.Location = new Point(220, 244); _chkAutostart.Size = new Size(200, 24);
            _chkAutostart.Click += (s, e) => ToggleAutostart();
            g2.Controls.Add(_chkAutostart);

            var g3 = new GroupBox();
            g3.Text = "③ 添加：手动加 IP，或直接输入服务器名自动解析出 IP";
            g3.Location = new Point(456, 310); g3.Size = new Size(432, 240);
            Controls.Add(g3);

            var lblA = new Label();
            lblA.Text = "手动加 IP / 网段（如 103.40.13.5 、115.231.235.0/24）";
            lblA.Location = new Point(14, 18); lblA.Size = new Size(404, 16);
            g3.Controls.Add(lblA);

            _txtIp.Location = new Point(14, 36); _txtIp.Size = new Size(250, 24);
            _txtIp.Font = UiFont(10f, FontStyle.Regular);
            g3.Controls.Add(_txtIp);
            _txtNote.Location = new Point(272, 36); _txtNote.Size = new Size(146, 24);
            _txtNote.Text = "备注";
            g3.Controls.Add(_txtNote);
            _btnAdd.Text = "加入拦截清单";
            _btnAdd.Location = new Point(14, 64); _btnAdd.Size = new Size(404, 26);
            _btnAdd.Click += (s, e) => AddManual();
            g3.Controls.Add(_btnAdd);

            var lblB = new Label();
            lblB.Text = "按服务器名加 IP（先用下面的扫描建立『名字↔IP』表）";
            lblB.Location = new Point(14, 100); lblB.Size = new Size(404, 16);
            g3.Controls.Add(lblB);

            _txtName.Location = new Point(14, 118); _txtName.Size = new Size(250, 24);
            _txtName.Font = UiFont(10f, FontStyle.Regular);
            g3.Controls.Add(_txtName);
            _btnAddName.Text = "查名字并加入";
            _btnAddName.Location = new Point(272, 118); _btnAddName.Size = new Size(146, 24);
            _btnAddName.Click += (s, e) => AddByName();
            g3.Controls.Add(_btnAddName);

            _btnScan.Text = "扫描已知服务器，建立/刷新 名字↔IP 表";
            _btnScan.Location = new Point(14, 148); _btnScan.Size = new Size(404, 26);
            _btnScan.Click += (s, e) => DoScan();
            g3.Controls.Add(_btnScan);

            _lblHint.Location = new Point(14, 178); _lblHint.Size = new Size(404, 20);
            _lblHint.ForeColor = Color.DimGray;
            _lblHint.Text = "解析不到就先点扫描（约 20-60 秒建立映射表）";
            g3.Controls.Add(_lblHint);

            var g5 = new GroupBox();
            g5.Text = "⑤ 操作记录";
            g5.Location = new Point(12, 560); g5.Size = new Size(876, 180);
            Controls.Add(g5);
            _txtLog.Location = new Point(14, 22); _txtLog.Size = new Size(848, 138);
            _txtLog.Multiline = true; _txtLog.ReadOnly = true; _txtLog.ScrollBars = ScrollBars.Vertical;
            _txtLog.BackColor = Color.FromArgb(250, 250, 250); _txtLog.Font = UiFont(9f, FontStyle.Regular);
            g5.Controls.Add(_txtLog);

            _timer.Interval = 1500;
            _timer.Tick += (s, e) => OnTick();
            Load += (s, e) =>
            {
                RefreshAll();
                Log("机制：WinDivert 内核层过滤，只匹配清单里的 IP/网段，命中即丢包（对其它流量零影响）。");
                Log("判定提示：③ 列写『全部命中现规则』的 IP，整段拦不会多拦到你想留的服。");
                _timer.Start();
            };
            FormClosing += (s, e) =>
            {
                if (!Blocker.IsActive) return;
                var r = MessageBox.Show(this,
                    "关闭窗口会停止 IP 拦截。\n\n是 = 停止并退出\n否 = 取消\n\n（想常驻请勾选「开机自动启动拦截」）",
                    "正在拦截中", MessageBoxButtons.YesNo, MessageBoxIcon.Warning);
                if (r != DialogResult.Yes) { e.Cancel = true; return; }
                Blocker.Stop();
            };
        }

        private void Log(string m)
        {
            _txtLog.AppendText("[" + DateTime.Now.ToString("HH:mm:ss") + "] " + m + "\r\n");
        }

        private void OnTick()
        {
            bool fresh;
            IpEngine.ReadHeartbeat(out fresh);
            if (Blocker.IsActive)
                _lblFw.Text = "拦截: 运行中（本窗口，句柄 " + Blocker.HandleCount + "，已丢弃 " + Interlocked.Read(ref Blocker.Dropped) + " 包）";
            else if (fresh)
                _lblFw.Text = "拦截: 运行中（常驻进程，由计划任务启动）";
            else
                _lblFw.Text = "拦截: 已停止";

            _btnToggle.Text = Blocker.IsActive ? "停止拦截"
                            : (fresh ? "停止常驻拦截" : "启动拦截");
            if (Blocker.IsActive) IpEngine.WriteHeartbeat();
            if (File.Exists(IpEngine.IpFile))
            {
                var st = File.GetLastWriteTime(IpEngine.IpFile);
                if (_ipFileStamp != DateTime.MinValue && st != _ipFileStamp && Blocker.IsActive)
                {
                    Log("检测到 ip_block.txt 变化，正在重载过滤器 ...");
                    Blocker.Stop();
                    var res = Blocker.Start(IpEngine.ReadEntries(), IpEngine.ExcludeUdpForNameLayer());
                    Log(res == "OK" ? ("已重载，覆盖 " + IpEngine.ReadEntries().Count + " 条地址。") : ("重载失败: " + res));
                }
                _ipFileStamp = st;
            }
        }

        private void RefreshAll()
        {
            Cursor = Cursors.WaitCursor;
            try
            {
                IpEngine.EnsureFile();
                _cands = IpEngine.MineCandidates();
                _lvCand.BeginUpdate(); _lvCand.Items.Clear();
                foreach (var c in _cands)
                {
                    var it = new ListViewItem(c.IsBlocked ? ("✔ " + c.Ip) : c.Ip);
                    it.SubItems.Add(c.Events.ToString());
                    it.SubItems.Add(c.Names.Count.ToString());
                    it.SubItems.Add(c.Sample);
                    it.Tag = c;
                    if (c.IsBlocked) it.ForeColor = Color.SeaGreen;
                    _lvCand.Items.Add(it);
                }
                _lvCand.EndUpdate();

                var entries = IpEngine.ReadEntries();
                _lvBlocked.BeginUpdate(); _lvBlocked.Items.Clear();
                foreach (var e in entries)
                {
                    var it = new ListViewItem(e.Address); it.SubItems.Add(e.Note); it.Tag = e;
                    _lvBlocked.Items.Add(it);
                }
                _lvBlocked.EndUpdate();

                _chkAutostart.Checked = IpEngine.AutostartInstalled();
                OnTick();
                Log("候选 " + _cands.Count + " 个 IP；清单 " + entries.Count + " 条。");
            }
            catch (Exception ex) { Log("× 刷新失败: " + ex.Message); }
            finally { Cursor = Cursors.Default; }
        }

        private void ToggleBlocking()
        {
            if (Blocker.IsActive)
            {
                Blocker.Stop();
                IpEngine.ClearHeartbeat();
                Log("已停止本窗口的 IP 拦截。");
            }
            else
            {
                bool fresh;
                IpEngine.ReadHeartbeat(out fresh);
                if (fresh)
                {
                    var resident = IpEngine.ResidentInstance();   // 只认心跳里那个 PID，不误杀界面窗口
                    if (resident != null) { try { resident.Kill(); } catch { } }
                    IpEngine.ClearHeartbeat();
                    Log("已停止常驻拦截进程 " + (resident != null ? resident.Id.ToString() : "") + "。");
                    Log("提示：开机自启仍开着，下次登录会再启动；要彻底关掉请取消勾选「开机自动启动拦截」。");
                }
                else
                {
                    var entries = IpEngine.ReadEntries();
                    if (entries.Count == 0) { Log("清单是空的，先加 IP。"); return; }
                    var res = Blocker.Start(entries, IpEngine.ExcludeUdpForNameLayer());
                    Log(res == "OK"
                        ? ("已启动拦截，覆盖 " + entries.Count + " 条地址（句柄 " + Blocker.HandleCount + "）。")
                        : ("启动失败: " + res));
                }
            }
            OnTick();
        }

        private void ToggleAutostart()
        {
            if (_chkAutostart.Checked)
                Log("安装开机自启: " + IpEngine.InstallAutostart());
            else
                Log("移除开机自启: " + IpEngine.RemoveAutostart());
            _chkAutostart.Checked = IpEngine.AutostartInstalled();
        }

        private void BlockSelected()
        {
            if (_lvCand.SelectedItems.Count == 0) { Log("请先在 ① 里选中要拦的 IP。"); return; }
            var entries = IpEngine.ReadEntries();
            int added = 0;
            foreach (ListViewItem it in _lvCand.SelectedItems)
            {
                var c = (Candidate)it.Tag;
                if (entries.Any(e => IpEngine.SameBaseAddress(e.Address, c.Ip))) continue;
                var note = c.Names.Count > 0
                    ? (c.Sample.Length > 40 ? c.Sample.Substring(0, 40) + "…" : c.Sample)
                    : ("日志拉黑 " + c.Events + " 次");
                entries.Add(new IpEntry { Address = c.Ip, Note = note });
                added++;
            }
            IpEngine.WriteEntries(entries);
            Log("已加入 " + added + " 个 IP（共 " + entries.Count + " 条）。");
            if (Blocker.IsActive) { Blocker.Stop(); Blocker.Start(IpEngine.ReadEntries(), IpEngine.ExcludeUdpForNameLayer()); }
            RefreshAll();
        }

        private void UnblockSelected()
        {
            if (_lvBlocked.SelectedItems.Count == 0) { Log("请先在 ② 里选中要解除的条目。"); return; }
            var del = new HashSet<string>(_lvBlocked.SelectedItems.Cast<ListViewItem>()
                .Select(i => ((IpEntry)i.Tag).Address), StringComparer.Ordinal);
            var entries = IpEngine.ReadEntries().Where(e => !del.Contains(e.Address)).ToList();
            IpEngine.WriteEntries(entries);
            foreach (var a in del) { string bb; List<int> pp; IpEngine.SplitExempt(a, out bb, out pp); IpEngine.RemoveLinksForIp(bb); }   // V-07
            Log("已解除 " + del.Count + " 条，剩余 " + entries.Count + " 条。");
            if (Blocker.IsActive) { Blocker.Stop(); Blocker.Start(entries, IpEngine.ExcludeUdpForNameLayer()); }
            RefreshAll();
        }

        private void ClearAll()
        {
            if (MessageBox.Show(this, "清空整个 IP 拦截清单并停止拦截？", "确认",
                    MessageBoxButtons.YesNo, MessageBoxIcon.Warning) != DialogResult.Yes) return;
            Blocker.Stop();
            IpEngine.WriteEntries(new List<IpEntry>());
            Log("已清空清单并停止拦截。");
            RefreshAll();
        }

        private void AddManual()
        {
            var s = _txtIp.Text.Trim();
            if (!IpEngine.IsValidAddress(s)) { Log("× 不是合法的 IPv4 或 CIDR: " + s); return; }
            // V-02: 按"基础地址"判重/更新（103.40.13.58!33030 与 103.40.13.58 是同一条），
            //       与 CLI --add / 统一界面保持一致，避免重复条目把"放行端口"例外废掉。
            var entries = IpEngine.ReadEntries();
            var note = _txtNote.Text.Trim();
            var act = IpEngine.UpsertEntry(entries, s, note == "备注" ? "" : note);
            IpEngine.WriteEntries(entries);
            _txtIp.Clear();
            Log((act == "added" ? "已添加 " : "已更新 ") + s + "，共 " + entries.Count + " 条。");
            if (Blocker.IsActive) { Blocker.Stop(); Blocker.Start(IpEngine.ReadEntries(), IpEngine.ExcludeUdpForNameLayer()); }
            RefreshAll();
        }

        /// <summary>输入服务器名 -> 自动解析出 IP -> 加入拦截清单。</summary>
        private void AddByName()
        {
            var s = _txtName.Text.Trim();
            if (s.Length == 0) { Log("请输入服务器名（可只写片段，如「無人永生」）。"); return; }
            try
            {
                List<string> names;
                var added = IpEngine.AddNameToBlockList(s, out names);
                if (names.Count == 0)
                {
                    Log("× 名字↔IP 表里没有『" + s + "』（表现有 " + IpEngine.ReadNameMap().Count + " 条）。");
                    Log("  点「扫描已知服务器」重建映射表（约 20-60 秒），再试。");
                    return;
                }
                Log("匹配到 " + names.Count + " 个服名：" + string.Join(" | ", names.Take(5).ToArray()));
                if (added.Count == 0) Log("这些服名对应的 IP 都已在拦截清单里。");
                else
                {
                    Log("已加入拦截清单 " + added.Count + " 个 IP：" + string.Join(", ", added.ToArray()));
                    if (Blocker.IsActive) { Blocker.Stop(); Blocker.Start(IpEngine.ReadEntries(), IpEngine.ExcludeUdpForNameLayer()); }
                }
                _txtName.Clear();
                RefreshAll();
            }
            catch (Exception ex) { Log("× 失败: " + ex.Message); }
        }

        private void DoScan()
        {
            if (MessageBox.Show(this,
                    "扫描已知服务器来建立『名字↔IP』表？\n\n" +
                    "会对日志里出现过的全部 endpoint 各发一次 A2S 查询，约 20-60 秒，只读不影响其它程序。",
                    "扫描", MessageBoxButtons.YesNo, MessageBoxIcon.Question) != DialogResult.Yes) return;
            Cursor = Cursors.WaitCursor;
            _btnScan.Enabled = false;
            Log("开始扫描已知服务器 ...");
            Application.DoEvents();
            try
            {
                var res = IpEngine.SweepNames(64, 1200, (d, t) => { if (d % 500 == 0) { Log("  进度 " + d + "/" + t); Application.DoEvents(); } });
                Log("扫描完成：endpoint " + res.Scanned + " 个，拿到名字 " + res.Found + " 个，映射表新增 " + res.Added + " 条。");
                Log("映射表现在共 " + IpEngine.ReadNameMap().Count + " 条。");
            }
            catch (Exception ex) { Log("× 扫描失败: " + ex.Message); }
            finally { Cursor = Cursors.Default; _btnScan.Enabled = true; }
        }
    }

    // ------------------------------------------------------------------ 入口
    // IP 拦截层：由合并后的 FilterTool.exe 调用（Program.Run / MainForm 被工具箱托管）
    internal static class Program
    {
        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool AttachConsole(int dwProcessId);

        [DllImport("kernel32.dll")]
        private static extern IntPtr GetStdHandle(int nStdHandle);

        public static void InitRoot()
        {
            try { IpEngine.Root = Path.GetDirectoryName(Application.ExecutablePath); }
            catch { IpEngine.Root = AppDomain.CurrentDomain.BaseDirectory; }
            if (string.IsNullOrEmpty(IpEngine.Root)) IpEngine.Root = AppDomain.CurrentDomain.BaseDirectory;
        }

        /// <summary>IP 拦截层的命令行入口（由合并后的总入口分发）。</summary>
        public static int Run(string[] args)
        {
            InitRoot();
            // 旧版本按名字解析时可能写入裸 IP；同一 IP 上还有别的服名时会造成误拦。
            // 启动任何命令行操作前先做一次幂等修复（--selftest 走 SelfTest.Run，不经过这里）。
            try { IpEngine.RepairSharedNameBlocks(null); } catch { }
            return RunCli(args);
        }

        /// <summary>跑一条外部命令并把输出拼成一行（--migrate-engine 用）。</summary>
        private static string RunCmd(string file, string args)
        {
            try
            {
                var psi = new ProcessStartInfo(file, args)
                {
                    UseShellExecute = false,
                    CreateNoWindow = true,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    StandardOutputEncoding = Encoding.GetEncoding(936),
                    StandardErrorEncoding = Encoding.GetEncoding(936)
                };
                using (var pr = Process.Start(psi))
                {
                    var ob = new StringBuilder();
                    var eb = new StringBuilder();
                    pr.OutputDataReceived += (s, e) => { if (e.Data != null) ob.Append(e.Data).Append(' '); };
                    pr.ErrorDataReceived += (s, e) => { if (e.Data != null) eb.Append(e.Data).Append(' '); };
                    pr.BeginOutputReadLine();
                    pr.BeginErrorReadLine();
                    if (!pr.WaitForExit(20000)) { try { pr.Kill(); } catch { } return "TIMEOUT"; }
                    pr.WaitForExit();
                    var o = (ob.ToString() + " " + eb.ToString()).Trim();
                    return o.Length > 0 ? o : ("exit " + pr.ExitCode);
                }
            }
            catch (Exception ex) { return "ERROR " + ex.Message; }
        }

        private static void BindConsole()
        {
            // 与 FilterTool.BindConsole 同一策略：先看有没有继承来的 stdout 句柄（管道/重定向/CI 捕获），
            // 不能先 AttachConsole —— 那会把标准句柄换成控制台的，外部脚本就再也读不到输出。
            try
            {
                var h = GetStdHandle(-11);
                if (h == IntPtr.Zero || h == new IntPtr(-1))
                {
                    try { AttachConsole(-1); } catch { }
                    h = GetStdHandle(-11);
                }
                if (h == IntPtr.Zero || h == new IntPtr(-1)) return;
                var fs = new FileStream(new Microsoft.Win32.SafeHandles.SafeFileHandle(h, false), FileAccess.Write, 1);
                var sw = new StreamWriter(fs, Encoding.UTF8) { AutoFlush = true };
                Console.SetOut(sw);
            }
            catch { }
        }

        private static IEnumerable<Control> Descendants(Control root)
        {
            foreach (Control c in root.Controls)
            {
                yield return c;
                foreach (var g in Descendants(c)) yield return g;
            }
        }

        private static int RunCli(string[] args)
        {
            BindConsole();
            var a0 = args[0].Trim().ToLowerInvariant();
            try
            {
                if (a0 == "--scan")
                {
                    int timeout = 900;
                    if (args.Length > 1) int.TryParse(args[1], out timeout);
                    var eps = IpEngine.CollectKnownEndpoints();
                    Console.WriteLine("扫描已知服务器：共 " + eps.Count + " 个 endpoint，并发 64，超时 " + timeout + "ms ...");
                    var sw = Stopwatch.StartNew();
                    var res = IpEngine.SweepNames(64, timeout, (d, total) => Console.WriteLine("  进度 " + d + "/" + total));
                    Console.WriteLine("完成：扫描 " + res.Scanned + " 个，拿到名字 " + res.Found + " 个，名字↔IP 表新增 " + res.Added + " 条，用时 " + (int)sw.Elapsed.TotalSeconds + " 秒。");
                    Console.WriteLine("映射表: " + IpEngine.NameMapFile);
                    return 0;
                }
                if (a0 == "--resolve")
                {
                    if (args.Length < 2) { Console.WriteLine("用法: --resolve \"<服名或片段>\""); return 2; }
                    string how;
                    List<string> names;
                    var ips = IpEngine.ResolveIps(args[1], out how, out names);
                    if (names.Count == 0)
                    {
                        Console.WriteLine("名字↔IP 表里没有匹配项（" + how + "）。");
                        Console.WriteLine("先执行: FilterTool.exe --scan（或界面里点「扫描已知服务器」）");
                        return 1;
                    }
                    Console.WriteLine("解析依据: " + how);
                    Console.WriteLine("匹配到 " + names.Count + " 个服名：");
                    foreach (var n in names.Take(20)) Console.WriteLine("   " + n);
                    if (names.Count > 20) Console.WriteLine("   ...（其余 " + (names.Count - 20) + " 个省略）");
                    Console.WriteLine("会被拦截的 IP（已做支持度过滤，" + ips.Count + " 个）：");
                    foreach (var ip in ips) Console.WriteLine("   " + ip);
                    return 0;
                }
                if (a0 == "--add-name")
                {
                    if (args.Length < 2) { Console.WriteLine("用法: --add-name \"<服名或片段>\""); return 2; }
                    List<string> names;
                    var added = IpEngine.AddNameToBlockList(args[1], out names);
                    if (names.Count == 0)
                    {
                        Console.WriteLine("名字↔IP 表里没有匹配项，无法定位 IP。");
                        Console.WriteLine("先执行: FilterTool.exe --scan（约 20-60 秒），或界面里点「扫描已知服务器」");
                        return 1;
                    }
                    Console.WriteLine("匹配到 " + names.Count + " 个服名：" + string.Join(" | ", names.Take(5).ToArray()));
                    if (added.Count == 0) { Console.WriteLine("这些服名对应的 IP 都已在拦截清单里。"); return 0; }
                    Console.WriteLine("已加入拦截清单 " + added.Count + " 个 IP：" + string.Join(", ", added.ToArray()));
                    Console.WriteLine("常驻进程会在 ~5 秒内自动重载 ip_block.txt。");
                    return 0;
                }
                if (a0 == "--pending")
                {
                    var pend = IpEngine.ReadPending();
                    if (pend.Count == 0) { Console.WriteLine("待解析名单是空的。"); return 0; }
                    Console.WriteLine("待解析服名 " + pend.Count + " 个（先用名字规则拦着，检测到 IP 后会自动补拦）：");
                    foreach (var kv in pend) Console.WriteLine("   " + kv.Name.PadRight(34) + " 加入于 " + kv.Added + (kv.Rule.Length > 0 && kv.Rule != kv.Name ? ("   规则: " + kv.Rule) : ""));
                    Console.WriteLine();
                    Console.WriteLine("立即尝试解析（必要时扫描）：FilterTool.exe --resolve-pending");
                    return 0;
                }
                if (a0 == "--resolve-pending")
                {
                    var n = IpEngine.ResolvePending(true, 0, Console.WriteLine);
                    Console.WriteLine("本轮新补进 IP 清单：" + n + " 个；仍待解析 " + IpEngine.ReadPending().Count + " 个。");
                    return 0;
                }
                if (a0 == "--help" || a0 == "-h" || a0 == "/?")
                {
                    Console.WriteLine("SteamServerFilter IP 拦截（WinDivert 内核层丢包，按 IP / 网段）");
                    Console.WriteLine("  IpBlock.exe                    打开界面");
                    Console.WriteLine("  IpBlock.exe --run [秒数]       前台驻留拦截（不给秒数则一直跑，供开机自启用）");
                    Console.WriteLine("  IpBlock.exe --status           清单 / 拦截状态 / 自启状态");
                    Console.WriteLine("  IpBlock.exe --list             列出拦截清单");
                    Console.WriteLine("  IpBlock.exe --candidates       列出候选 IP（含安全性判定）");
                    Console.WriteLine("  IpBlock.exe --scan [超时ms]    扫描已知服务器，建立/刷新『名字↔IP』表");
                    Console.WriteLine("  IpBlock.exe --resolve \"<服名>\"  查这个名字对应哪个 IP");
                    Console.WriteLine("  IpBlock.exe --add-name \"<服名>\" 按名字自动把对应 IP 加入拦截清单");
                    Console.WriteLine("  IpBlock.exe --block-family     一键拦下所有『服名全部命中现规则』的 IP");
                    Console.WriteLine("  IpBlock.exe --add <ip|cidr> [备注]");
                    Console.WriteLine("  IpBlock.exe --remove <ip|cidr>");
                    Console.WriteLine("  IpBlock.exe --verify <ip:port> 测这个 endpoint 还能不能收到应答");
                    Console.WriteLine("  IpBlock.exe --autostart on|off 开机自启");
                    return 0;
                }
                if (a0 == "--status")
                {
                    Console.WriteLine("清单文件: " + IpEngine.IpFile);
                    Console.WriteLine(IpEngine.StatusText());
                    var others = IpEngine.OtherInstances();
                    var resident = IpEngine.ResidentInstance();
                    Console.WriteLine("常驻拦截进程: " + (resident != null ? resident.Id.ToString() : "无"));
                    if (resident == null && others.Length > 0)
                        Console.WriteLine("（另有 " + others.Length + " 个 FilterTool 窗口进程，不计入常驻拦截）");
                    return 0;
                }
                if (a0 == "--list")
                {
                    var e = IpEngine.ReadEntries();
                    Console.WriteLine("清单 " + e.Count + " 条：");
                    foreach (var x in e)
                    {
                        string a2; List<int> p2;
                        IpEngine.SplitExempt(x.Address, out a2, out p2);
                        var tag = p2.Count > 0 ? ("  [放行端口 " + string.Join(",", p2.Select(p => p.ToString()).ToArray()) + "]") : "";
                        Console.WriteLine("  " + x.Address.PadRight(24) + tag + (x.Note.Length > 0 ? " # " + x.Note : ""));
                    }
                    return 0;
                }
                if (a0 == "--bind-name")
                {
                    if (args.Length < 3) { Console.WriteLine("用法: --bind-name \"<服名>\" <ip[:端口]> [名字规则]"); return 2; }
                    var nm = args[1].Trim();
                    var ep = args[2].Trim();
                    var rule = args.Length > 3 ? args[3].Trim() : nm;
                    var ipOnly = ep;
                    var c = ep.LastIndexOf(':');
                    if (c > 0) ipOnly = ep.Substring(0, c);
                    if (!IpEngine.IsValidAddress(ipOnly)) { Console.WriteLine("不是合法地址: " + ipOnly); return 2; }
                    if (c <= 0) ep = ep + ":27015";
                    IpEngine.UpsertNameMap(nm, ep);
                    IpEngine.AddLink(rule, ipOnly, nm);
                    var wasPending = IpEngine.ReadPending().Any(x => string.Equals(x.Name, nm, StringComparison.OrdinalIgnoreCase));
                    if (wasPending) IpEngine.RemovePending(nm);
                    Console.WriteLine("已认定：「" + nm + "」= " + ep);
                    Console.WriteLine("  · 名字→IP 表已写入（以后 --resolve \"" + nm + "\" 直接命中 " + ipOnly + "）");
                    Console.WriteLine("  · 已关联到名字规则「" + rule + "」：删这条规则时会一并释放 " + ipOnly);
                    if (wasPending) Console.WriteLine("  · 已从待解析名单移除");
                    var cur = IpEngine.ReadEntries();
                    var hit = cur.FirstOrDefault(e =>
                    {
                        string b2; List<int> p2; IpEngine.SplitExempt(e.Address, out b2, out p2);
                        return string.Equals(b2, ipOnly, StringComparison.Ordinal);
                    });
                    Console.WriteLine(hit != null
                        ? ("  · 该地址已在 IP 拦截清单里：" + hit.Address)
                        : ("  · 注意：该地址还不在 IP 拦截清单里，需要的话执行 --add " + ipOnly));
                    return 0;
                }
                if (a0 == "--exempt" || a0 == "--unexempt")
                {
                    if (args.Length < 2) { Console.WriteLine("用法: --exempt <地址> <端口[,端口...]>   /   --unexempt <地址>"); return 2; }
                    string baseAddr; List<int> cur;
                    IpEngine.SplitExempt(args[1], out baseAddr, out cur);
                    uint x1, y1;
                    if (!IpEngine.TryParseRange(baseAddr, out x1, out y1)) { Console.WriteLine("不是合法地址: " + baseAddr); return 2; }
                    var entries2 = IpEngine.ReadEntries();
                    int idx = entries2.FindIndex(en =>
                    {
                        string a2; List<int> p2;
                        IpEngine.SplitExempt(en.Address, out a2, out p2);
                        return string.Equals(a2, baseAddr, StringComparison.Ordinal);
                    });
                    if (idx < 0) { Console.WriteLine("清单里没有这个地址: " + baseAddr + "（先用 --add 加它）"); return 1; }
                    var ports = a0 == "--unexempt" ? new List<int>() : cur;
                    if (a0 == "--exempt" && args.Length >= 3)
                        foreach (var t in args[2].Split(new[] { ',', ' ' }, StringSplitOptions.RemoveEmptyEntries))
                        {
                            int p;
                            if (int.TryParse(t, out p) && p >= 1 && p <= 65535 && !ports.Contains(p)) ports.Add(p);
                        }
                    ports.Sort();
                    entries2[idx].Address = IpEngine.JoinExempt(baseAddr, ports);
                    IpEngine.WriteEntries(entries2);
                    Console.WriteLine(ports.Count > 0
                        ? ("已设置放行端口: " + baseAddr + " 放行 " + string.Join(",", ports.Select(p => p.ToString()).ToArray()) +
                           "（这个地址的其它端口照拦；运行中约 5 秒内自动生效）")
                        : ("已取消放行端口: " + baseAddr + " 恢复为整个地址都拦"));
                    return 0;
                }
                if (a0 == "--tray")
                {
                    // 无参数 = 只看状态，绝不改状态。原先无参数被当成 off：
                    // --logs-task 删任务 / --autostart 删开机自启 / --tray、--name-layer 直接关掉。
                    if (args.Length < 2)
                    {
                        Console.WriteLine("托盘图标: " + (TrayHost.Enabled ? "显示（改后重启常驻生效）" : "不显示"));
                        Console.WriteLine("用法: --tray on|off");
                        return 0;
                    }
                    var vRaw = args[1].Trim().ToLowerInvariant();
                    if (vRaw != "on" && vRaw != "off")
                    {
                        Console.WriteLine("只接受 on / off（查状态请不带参数）。收到: " + args[1]);
                        return 2;
                    }
                    var on = vRaw == "on";
                    TrayHost.Enabled = on;
                    Console.WriteLine("常驻进程托盘图标已设为 " + (on ? "显示" : "不显示") +
                                      "（" + Path.Combine(IpEngine.Root, "tray.txt") + "）；重启常驻拦截后生效。");
                    return 0;
                }
                if (a0 == "--config-audit")
                {
                    foreach (var l in Config.Audit()) Console.WriteLine(l);
                    return 0;
                }
                if (a0 == "--config-migrate")
                {
                    foreach (var l in Config.Migrate()) Console.WriteLine(l);
                    Console.WriteLine("下一步: schtasks /Run /TN \"" + IpEngine.TaskName + "\" 让常驻进程重读。");
                    return 0;
                }
                if (a0 == "--config")
                {
                    if (args.Length == 1)
                    {
                        Console.WriteLine("统一开关文件: " + Config.File);
                        foreach (var l in Config.Dump()) Console.WriteLine("  " + l);
                        Console.WriteLine("用法: --config <key> <value>  |  --config audit  |  --config migrate");
                        Console.WriteLine("      key: name-layer on|off · mode both|name · tray on|off · log-keep 天数 · active-profile（已统一，固定 custom）");
                        return 0;
                    }
                    var k1 = args[1].Trim().ToLowerInvariant();
                    if (k1 == "audit")
                    {
                        foreach (var l in Config.Audit()) Console.WriteLine(l);
                        return 0;
                    }
                    if (k1 == "migrate")
                    {
                        foreach (var l in Config.Migrate()) Console.WriteLine(l);
                        Console.WriteLine("下一步: schtasks /Run /TN \"" + IpEngine.TaskName + "\" 让常驻进程重读。");
                        return 0;
                    }
                    if (args.Length < 3) { Console.WriteLine("用法: --config <key> <value>"); return 2; }
                    var v1 = args[2].Trim();
                    if (k1 == "name-layer") NameLayer.Enabled = v1.ToLowerInvariant().StartsWith("on");
                    else if (k1 == "mode") NameLayer.NameOnlyMode = v1.ToLowerInvariant().StartsWith("name");
                    else if (k1 == "tray") TrayHost.Enabled = v1.ToLowerInvariant().StartsWith("on");
                    else if (k1 == "log-keep") { int dd; if (int.TryParse(v1, out dd)) IpEngine.LogRetentionDays = dd; }
                    else if (k1 == "active-profile") SteamServerFilterRules.Engine.SetActiveProfile(v1);
                    else { Console.WriteLine("未知键: " + k1); return 2; }
                    Console.WriteLine(k1 + " = " + v1 + " 已写入 " + Config.File);
                    return 0;
                }

                if (a0 == "--migrate-engine")
                {
                    Console.WriteLine("迁移到内置名字层（退役 SteamServerFilter 双轨）");
                    int step = 0;
                    // 1) 停用旧引擎的开机任务
                    step++;
                    Console.WriteLine("  " + step + ") 删除旧计划任务 SteamServerFilter Startup（旧引擎 SteamServerFilter.exe 已归档到 _archive\\legacy-binaries）：");
                    Console.WriteLine("     " + Lifecycle.DeleteLegacyTask());
                    // 2) 结束旧引擎进程
                    step++;
                    var killed = 0;
                    foreach (var pr in Process.GetProcessesByName("SteamServerFilter"))
                    {
                        try { pr.Kill(); killed++; } catch { }
                    }
                    Console.WriteLine("  " + step + ") 已结束旧引擎进程 " + killed + " 个（正常情况下 0 个：旧入口已停用）");
                    // 3) 打开内置名字层
                    step++;
                    NameLayer.Enabled = true;
                    Console.WriteLine("  " + step + ") 内置名字层开关已打开（" + NameLayer.FlagFile + "）");
                    // 4) 回滚说明
                    Console.WriteLine("  回滚：FilterTool.exe --name-layer off");
                    Console.WriteLine("        如需恢复旧引擎，把 _archive\\legacy-binaries\\SteamServerFilter.exe 移回项目根；");
                    Console.WriteLine("        旧任务已删除，正常不需要恢复（如确需开机自启，重新创建任务指向新入口 FilterTool.exe --run）");
                    Console.WriteLine("  下一步：重启常驻拦截以应用 —— schtasks /Run /TN \"" + IpEngine.TaskName + "\"");
                    return 0;
                }
                if (a0 == "--mode")
                {
                    if (args.Length < 2)
                    {
                        Console.WriteLine("当前拦截模式: " + NameLayer.ModeName + "（" + NameLayer.ModeFile + "）");
                        Console.WriteLine("  both = IP 清单 + 名字规则（默认）");
                        Console.WriteLine("  name = 只按服务器名拦；ip_block.txt 完全不参与（不会有按 IP 连坐的误伤）");
                        return 0;
                    }
                    var m = args[1].Trim().ToLowerInvariant();
                    var nameOnly = m.StartsWith("name");
                    NameLayer.NameOnlyMode = nameOnly;
                    Console.WriteLine("拦截模式已写入 " + NameLayer.ModeFile + "：" + (nameOnly ? "name（纯名字）" : "both（IP + 名字）"));
                    if (nameOnly && !NameLayer.Enabled)
                    {
                        NameLayer.Enabled = true;
                        Console.WriteLine("纯名字模式必须靠内置名字层干活，已顺手打开名字层开关（name_layer.txt=on）。");
                    }
                    bool freshM; string nsM;
                    IpEngine.HeartbeatBlocking(out freshM, out nsM);
                    var resM = IpEngine.ResidentInstance();
                    if (resM != null)
                        Console.WriteLine("常驻拦截进程 " + resM.Id + " 会在几秒内自动切换（按新模式重建句柄）。");
                    else
                        Console.WriteLine("★ 当前没有常驻拦截进程 —— 请执行 FilterTool.exe --run 或点界面 ④ 的「启动 IP 拦截」。");
                    return 0;
                }
                if (a0 == "--name-layer")
                {
                    // 无参数 = 只看状态，绝不改状态。原先无参数被当成 off：
                    // --logs-task 删任务 / --autostart 删开机自启 / --tray、--name-layer 直接关掉。
                    if (args.Length < 2)
                    {
                        Console.WriteLine("内置名字层: " + (NameLayer.Enabled ? "已启用" : "已关闭") + " · 规则 " + SteamServerFilterRules.Engine.ReadEngineRules().Count + " 条 · 常驻进程 " + (IpEngine.HeartbeatField("namelayer") == "yes" ? "运行中" : "未运行"));
                        Console.WriteLine("用法: --name-layer on|off");
                        return 0;
                    }
                    var vRaw = args[1].Trim().ToLowerInvariant();
                    if (vRaw != "on" && vRaw != "off")
                    {
                        Console.WriteLine("只接受 on / off（查状态请不带参数）。收到: " + args[1]);
                        return 2;
                    }
                    var on = vRaw == "on";
                    NameLayer.Enabled = on;
                    Console.WriteLine("内置名字层已" + (on ? "启用" : "关闭") + "（写入 " + NameLayer.FlagFile + "）");
                    if (on)
                    {
                        // V-30: 绝不在 CLI 进程里 Start() —— 那只是本进程句柄，命令行退出就没了，
                        // 却会让用户以为"已经在拦"。真正干活的只有常驻进程（--run）。
                        bool freshN; string nsN;
                        IpEngine.HeartbeatBlocking(out freshN, out nsN);
                        var residentN = IpEngine.ResidentInstance();
                        if (residentN != null)
                            Console.WriteLine("常驻拦截进程 " + residentN.Id + " 正在运行：它会在几秒内按开关启停名字层" +
                                              "（并同步把 IP 层句柄改成 not udp）。");
                        else
                        {
                            Console.WriteLine("★ 当前没有常驻拦截进程 —— 名字层现在【不会】拦截任何东西。");
                            Console.WriteLine("  请执行 FilterTool.exe --run，或点界面 ④ 的「启动 IP 拦截」。");
                        }
                    }
                    else
                    {
                        NameLayer.Stop();
                        Console.WriteLine("已停止。已封端点记录仍保留在 " + NameLayer.BlockedFile + "（重启后继续生效）。");
                    }
                    return 0;
                }
                if (a0 == "--name-blocked")
                {
                    NameLayer.ReloadBlocked();   // 独立进程里内存是空的，先读落盘的表
                    var list = NameLayer.BlockedList();
                    Console.WriteLine("按名字封掉的端点 " + list.Count + " 个（" + NameLayer.BlockedFile + "）：");
                    foreach (var kv in list.Take(60)) Console.WriteLine("   " + kv.Key.PadRight(24) + kv.Value);
                    if (list.Count > 60) Console.WriteLine("   ...（其余 " + (list.Count - 60) + " 个省略）");
                    Console.WriteLine("文件: " + NameLayer.SeenFile + " 记录见过的端点（供扫描发现新服）");
                    bool nf; string ns;
                    IpEngine.HeartbeatBlocking(out nf, out ns);
                    var running = NameLayer.IsRunning || (nf && IpEngine.HeartbeatField("namelayer") == "yes");
                    Console.WriteLine("当前名字层: " + (running ? ("运行中（" + (NameLayer.IsRunning ? "本进程" : "常驻进程") + "）")
                                                            : (NameLayer.Enabled ? "已启用未运行" : "关闭")));
                    return 0;
                }
                if (a0 == "--logs-prune")
                {
                    int days = IpEngine.LogRetentionDays;
                    if (args.Length > 1 && !int.TryParse(args[1], out days)) { Console.WriteLine("保留天数必须是整数: " + args[1]); return 2; }
                    Console.WriteLine("清理日志：保留最近 " + days + " 天（目录 " + IpEngine.LogDir + "）");
                    var r = IpEngine.PruneLogs(days, Console.WriteLine);
                    if (r.Examples.Count > 0) Console.WriteLine("  例如已删：" + string.Join(", ", r.Examples.ToArray()));
                    Console.WriteLine("  记录写到 " + Path.Combine(IpEngine.Root, "logs_prune.log"));
                    if (!IpEngine.LogTaskInstalled())
                        Console.WriteLine("  提示：定时任务未安装，执行 --logs-task on 让它每 3 天自动跑一次。");
                    return 0;
                }
                if (a0 == "--logs-keep")
                {
                    if (args.Length < 2) { Console.WriteLine("用法: --logs-keep <天数>   （当前 " + IpEngine.LogRetentionDays + " 天）"); return 2; }
                    int d;
                    if (!int.TryParse(args[1], out d) || d < 1) { Console.WriteLine("天数必须是正整数"); return 2; }
                    IpEngine.LogRetentionDays = d;
                    Console.WriteLine("已设置日志保留天数: " + IpEngine.LogRetentionDays + " 天");
                    // V-33: 任务命令行里烤的是 --logs-prune N，改了天数必须重装，否则仍按旧天数清理
                    if (IpEngine.LogTaskInstalled())
                        Console.WriteLine("已同步重装日志清理任务: " + IpEngine.InstallLogTask(d));
                    return 0;
                }
                if (a0 == "--logs-task")
                {
                    // 无参数 = 只看状态，绝不改状态。原先无参数被当成 off：
                    // --logs-task 删任务 / --autostart 删开机自启 / --tray、--name-layer 直接关掉。
                    if (args.Length < 2)
                    {
                        Console.WriteLine("日志清理任务: " + (IpEngine.LogTaskInstalled() ? ("已安装 · " + IpEngine.LogTaskName + " · 保留 " + IpEngine.LogRetentionDays + " 天") : "未安装"));
                        Console.WriteLine("用法: --logs-task on|off");
                        return 0;
                    }
                    var vRaw = args[1].Trim().ToLowerInvariant();
                    if (vRaw != "on" && vRaw != "off")
                    {
                        Console.WriteLine("只接受 on / off（查状态请不带参数）。收到: " + args[1]);
                        return 2;
                    }
                    var on = vRaw == "on";
                    if (on)
                    {
                        Console.WriteLine("安装「每 3 天清理日志」任务: " + IpEngine.InstallLogTask(IpEngine.LogRetentionDays));
                        Console.WriteLine("任务名: " + IpEngine.LogTaskName + "   保留 " + IpEngine.LogRetentionDays + " 天");
                    }
                    else Console.WriteLine("移除日志清理任务: " + IpEngine.RemoveLogTask());
                    return 0;
                }                if (a0 == "--candidates")
                {
                    var c = IpEngine.MineCandidates();
                    Console.WriteLine("候选 " + c.Count + " 个（按拉黑次数排序）：");
                    Console.WriteLine("{0,-16} {1,8} {2,6} {3,6}  {4}", "IP", "拉黑", "端口", "服名", "判定 / 示例");
                    foreach (var x in c)
                        Console.WriteLine("{0,-16} {1,8} {2,6} {3,6}  {4}   {5}",
                            x.Ip, x.Events, x.Ports, x.Names.Count, x.Verdict, x.Sample);
                    return 0;
                }
                if (a0 == "--block-family")
                {
                    var c = IpEngine.MineCandidates();
                    var pick = c.Where(x => x.Names.Count > 0 && x.Unwanted == x.Names.Count && !x.IsBlocked)
                                .OrderByDescending(x => x.Events).ToList();
                    if (pick.Count == 0) { Console.WriteLine("没有『服名全部命中现规则』的新候选。"); return 0; }
                    var entries = IpEngine.ReadEntries();
                    foreach (var x in pick)
                    {
                        entries.Add(new IpEntry { Address = x.Ip, Note = ("日志拉黑 " + x.Events + " 次；" + x.Sample).Trim() });
                        Console.WriteLine("加入: " + x.Ip + "   " + x.Verdict + "   " + x.Sample);
                    }
                    IpEngine.WriteEntries(entries);
                    Console.WriteLine("清单现在 " + entries.Count + " 条。用 --run 启动拦截。");
                    return 0;
                }
                if (a0 == "--add")
                {
                    if (args.Length < 2 || !IpEngine.IsValidAddress(args[1])) { Console.WriteLine("用法: --add <ip|cidr|ip:udp-port> [备注]   也支持 103.40.13.58!33030 这种放行端口写法"); return 2; }
                    // V-08: /0~/8 这种超大网段会按 ip.DstAddr/SrcAddr 双向丢包 = 本机 IPv4 全断。
                    int bpf; long bhosts;
                    if (IpEngine.IsBroadRange(args[1].Trim(), out bpf, out bhosts) &&
                        !args.Any(x => string.Equals(x, "--yes", StringComparison.OrdinalIgnoreCase)))
                    {
                        Console.WriteLine("× " + args[1].Trim() + " 是超大网段（/" + bpf + "，约 " + bhosts + " 个地址）。");
                        Console.WriteLine("  按 IP 拦截是双向丢包，加进去等于本机这些地址的流量全部中断。");
                        Console.WriteLine("  确认要这么做请加 --yes 重跑：FilterTool.exe --add \"" + args[1].Trim() + "\" --yes");
                        return 3;
                    }
                    var entries = IpEngine.ReadEntries();
                    var note = args.Length > 2 ? args[2] : "";
                    var act = IpEngine.UpsertEntry(entries, args[1].Trim(), note);
                    IpEngine.WriteEntries(entries);
                    string ba; List<int> ex;
                    IpEngine.SplitExempt(args[1].Trim(), out ba, out ex);
                    Console.WriteLine((act == "added" ? "已加入 " : "已更新 ") + args[1] +
                                      (ex.Count > 0 ? ("（放行端口 " + string.Join(",", ex.Select(p => p.ToString()).ToArray()) + "，其余照拦）") : "") +
                                      "，共 " + entries.Count + " 条。");
                    return 0;
                }
                if (a0 == "--remove")
                {
                    if (args.Length < 2) { Console.WriteLine("用法: --remove <ip|cidr>"); return 2; }
                    var entries = IpEngine.ReadEntries();
                    int before = entries.Count;
                    var gone = entries.Where(e => IpEngine.SameBaseAddress(e.Address, args[1].Trim())).Select(e => e.Address).ToList();
                    entries = entries.Where(e => !IpEngine.SameBaseAddress(e.Address, args[1].Trim())).ToList();
                    IpEngine.WriteEntries(entries);
                    string bg; List<int> pg;
                    IpEngine.SplitExempt(args[1].Trim(), out bg, out pg);
                    IpEngine.RemoveLinksForIp(bg);   // V-07: 同步清理关联，避免脏关联导致日后误删
                    Console.WriteLine("移除 " + (before - entries.Count) + " 条，剩余 " + entries.Count + " 条。");
                    if (gone.Count > 0) Console.WriteLine("（已同步清理这些地址的规则关联：" + string.Join(", ", gone.ToArray()) + "）");
                    return 0;
                }
                if (a0 == "--verify")
                {
                    if (args.Length < 2) { Console.WriteLine("用法: --verify <ip:port>"); return 2; }
                    var p = args[1].Split(':');
                    int port = p.Length > 1 ? int.Parse(p[1]) : 27015;
                    Console.WriteLine(args[1] + "  →  " + IpEngine.VerifyEndpoint(p[0], port));
                    return 0;
                }
                if (a0 == "--autostart")
                {
                    // 无参数 = 只看状态，绝不改状态。原先无参数被当成 off：
                    // --logs-task 删任务 / --autostart 删开机自启 / --tray、--name-layer 直接关掉。
                    if (args.Length < 2)
                    {
                        Console.WriteLine("开机自启任务查询：" + RunCmd("schtasks.exe", "/Query /TN \"" + IpEngine.TaskName + "\""));
                        Console.WriteLine("  常驻拦截: " + (IpEngine.ResidentInstance() != null ? "在跑" : "没在跑"));
                        Console.WriteLine("用法: --autostart on|off");
                        return 0;
                    }
                    var vRaw = args[1].Trim().ToLowerInvariant();
                    if (vRaw != "on" && vRaw != "off")
                    {
                        Console.WriteLine("只接受 on / off（查状态请不带参数）。收到: " + args[1]);
                        return 2;
                    }
                    var on = vRaw == "on";
                    Console.WriteLine((on ? "安装开机自启: " : "移除开机自启: ") + (on ? IpEngine.InstallAutostart() : IpEngine.RemoveAutostart()));
                    return 0;
                }
                if (a0 == "--run")
                {
                    int secs = 0;
                    if (args.Length > 1) int.TryParse(args[1], out secs);
                    // V-36: 模式判断必须在"清单是否为空"之前 —— 纯名字模式的卖点就是不依赖 ip_block.txt，
                    // 用户清空清单后不能反而拒绝启动。
                    bool nameOnly = NameLayer.NameOnlyMode;
                    bool wantName = NameLayer.Enabled || nameOnly;
                    var entries = IpEngine.ReadEntries();
                    if (entries.Count == 0 && !nameOnly)
                    {
                        Console.WriteLine("清单是空的，先 --add / --block-family；或用 --mode name 走纯名字模式。");
                        return 1;
                    }
                    string nameResult = "";
                    if (wantName)
                    {
                        nameResult = NameLayer.Start();
                        Console.WriteLine(nameResult == "OK"
                            ? ("内置名字层已启动：规则 " + SteamServerFilterRules.Engine.ReadEngineRules().Count +
                               " 条，按名字丢包不再依赖 SteamServerFilter。")
                            : ("内置名字层启动失败: " + nameResult));
                    }
                    if (nameOnly)
                    {
                        Console.WriteLine("拦截模式：纯名字（ip_block.txt 的 " + entries.Count + " 条地址不参与拦截）");
                        Console.WriteLine("已跳过 IP 层句柄 —— 只靠内置名字层按服名丢包。");
                        var delegated = Blocker.Start(new List<IpEntry>(), IpEngine.ExcludeUdpForNameLayer());
                        if (delegated != "OK") { Console.WriteLine("启动失败: " + delegated); return 1; }
                    }
                    else
                    {
                        var res = Blocker.Start(entries, nameResult == "OK");
                        Console.WriteLine(res == "OK"
                            ? ("已启动 IP 拦截：覆盖 " + entries.Count + " 条地址，句柄 " + Blocker.HandleCount +
                               (nameResult == "OK" ? "（过滤器已排除 udp，交给名字层）" : "") + ".")
                            : ("启动失败: " + res));
                        if (res != "OK") return 1;
                    }
                    if (!wantName) Console.WriteLine("内置名字层：关闭（--name-layer on 可启用）");

                    var stamp = File.GetLastWriteTime(IpEngine.IpFile);
                    var start = DateTime.Now;
                    var nextPending = DateTime.Now.AddSeconds(20);
                    int pendingBusy = 0;
                    var lastFlagStamp = NameLayer.FlagFile != null ? Config.ConfigStamp() : DateTime.MinValue;   // 3.2：合并为一个配置戳
                    var lastRuleStamp = File.Exists(IpEngine.RulesFile) ? File.GetLastWriteTime(IpEngine.RulesFile) : DateTime.MinValue;
                    var lastModeStamp = File.Exists(NameLayer.ModeFile) ? File.GetLastWriteTime(NameLayer.ModeFile) : DateTime.MinValue;
                    var errState = "";
                    var lastBeat = DateTime.Now;
                    var lastResidentCheck = DateTime.Now;
                    IpEngine.WriteHeartbeat(Blocker.IsActive, errState);

                    // 托盘图标（像 SteamServerFilter 一样在右下角，右键可停止并退出）
                    var trayStop = new bool[1];
                    if (TrayHost.Enabled)
                    {
                        var th = new Thread(() => TrayHost.Run(
                            "SteamServerFilter 拦截工具",
                            () =>
                            {
                                var mode = NameLayer.NameOnlyMode ? "纯名字" : "IP+名字";
                                return mode + " · 名字层" + (NameLayer.IsRunning ? "开" : "关") +
                                       " · 已封" + NameLayer.BlockedCount +
                                       " · 命中" + Interlocked.Read(ref NameLayer.NameHits) +
                                       " · 丢弃" + Interlocked.Read(ref Blocker.Dropped) + "\n" +
                                       "组服列表过滤：" + GroupServerFilter.StateText() +
                                       (GroupServerFilter.ResidentProcessId() > 0
                                           ? "（监视进程 PID " + GroupServerFilter.ResidentProcessId() + "）"
                                           : "（无监视进程）");
                            },
                            () =>
                            {
                                try
                                {
                                    Process.Start(new ProcessStartInfo(
                                        System.Reflection.Assembly.GetExecutingAssembly().Location)
                                    { UseShellExecute = true, WorkingDirectory = IpEngine.Root });
                                }
                                catch { }
                            },
                            () => { try { Process.Start(new ProcessStartInfo(IpEngine.Root) { UseShellExecute = true }); } catch { } },
                            () => { trayStop[0] = true; }));
                        th.IsBackground = true;
                        th.SetApartmentState(ApartmentState.STA);
                        th.Name = "tray";
                        th.Start();
                        Console.WriteLine("托盘图标已显示（右键可停止拦截并退出；--tray off 可关闭）。");
                    }

                    // 组服列表过滤是独立层（默认常开 auto=on）：确保它自己的监视进程在跑。
                    // 名字层这个循环不再 tick 它 —— 两层互不依赖，关掉名字层也不影响组服过滤。
                    if (GroupServerFilter.AutoEnabled)
                    {
                        string residentReport;
                        GroupServerFilter.EnsureResident(out residentReport);
                        Console.WriteLine(residentReport);
                    }

                    while (!trayStop[0])
                    {
                        Thread.Sleep(1000);
                        // 1.3：心跳 1s → 3s（fresh 阈值 15s，余量充足；SafeFile.Write 是"临时文件+Replace"，
                        //      降频直接减少 SSD 写入）。异常路径仍会立即写。
                        if ((DateTime.Now - lastBeat).TotalSeconds >= 3)
                        {
                            lastBeat = DateTime.Now;
                            IpEngine.WriteHeartbeat(Blocker.IsActive, errState);
                        }
                        // 组服过滤是独立层：监视进程若被外部结束或自身退出，这里每 10 秒兜底拉起一次。
                        // 没有这段时，--run 常驻也要等下次打开界面才会恢复注入（2026-11-04 实测到的失效路径）。
                        if ((DateTime.Now - lastResidentCheck).TotalSeconds >= 10)
                        {
                            lastResidentCheck = DateTime.Now;
                            try
                            {
                                if (GroupServerFilter.AutoEnabled && !GroupServerFilter.ResidentRunning())
                                {
                                    string residentRestart;
                                    GroupServerFilter.EnsureResident(out residentRestart);
                                    Console.WriteLine("组服过滤监视进程已重启: " + residentRestart);
                                    try
                                    {
                                        File.AppendAllText(Path.Combine(GroupServerFilter.Dir, "watchdog.log"),
                                            DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss") + " 重启组服过滤监视进程: " + residentRestart + "\r\n");
                                    }
                                    catch { }
                                    IpEngine.WriteHeartbeat(Blocker.IsActive, errState);
                                }
                            }
                            catch (Exception exRes) { errState = "ERROR: 组服监视进程重启失败 " + exRes.Message; }
                        }
                        if (secs > 0 && (DateTime.Now - start).TotalSeconds >= secs) break;

                        bool recoveryWantName = NameLayer.Enabled || NameLayer.NameOnlyMode;
                        if (recoveryWantName && !NameLayer.IsRunning &&
                            Config.ConfigStamp() == lastFlagStamp &&
                            (File.Exists(IpEngine.RulesFile) ? File.GetLastWriteTime(IpEngine.RulesFile) : DateTime.MinValue) == lastRuleStamp)
                        {
                            var nr = NameLayer.Start();
                            Console.WriteLine("重试启动内置名字层: " + nr);
                            Blocker.Stop();
                            var br = Blocker.Start(IpEngine.ReadEntries(), IpEngine.ExcludeUdpForNameLayer());
                            errState = nr != "OK" ? "ERROR: 名字层启动失败 " + nr : br == "OK" ? "" : "ERROR: " + br;
                            IpEngine.WriteHeartbeat(Blocker.IsActive, errState);
                            if (nr != "OK") Thread.Sleep(3000);
                        }
                        if (Blocker.IsRunning && !NameLayer.NameOnlyMode &&
                            Blocker.ExcludesUdp != IpEngine.ExcludeUdpForNameLayer())
                        {
                            var br = Blocker.Start(IpEngine.ReadEntries(), IpEngine.ExcludeUdpForNameLayer());
                            errState = br == "OK" ? "" : "ERROR: " + br;
                            IpEngine.WriteHeartbeat(Blocker.IsActive, errState);
                        }

                        if (!NameLayer.NameOnlyMode && !Blocker.IsActive &&
                            Config.ConfigStamp() == lastFlagStamp &&
                            (File.Exists(IpEngine.RulesFile) ? File.GetLastWriteTime(IpEngine.RulesFile) : DateTime.MinValue) == lastRuleStamp)
                        {
                            errState = "ERROR: 拦截句柄失效，正在重试";
                            for (int attempt = 1; attempt <= 3 && !Blocker.IsActive; attempt++)
                            {
                                Thread.Sleep(3000);
                                var rr = Blocker.Start(IpEngine.ReadEntries(), IpEngine.ExcludeUdpForNameLayer());
                                Console.WriteLine("重试启动 IP 拦截（第 " + attempt + " 次）: " + rr);
                                IpEngine.WriteHeartbeat(Blocker.IsActive, errState);
                            }
                            if (Blocker.IsActive)
                            {
                                errState = "";
                                stamp = File.GetLastWriteTime(IpEngine.IpFile);
                                Console.WriteLine("拦截已恢复。");
                            }
                            continue;
                        }

                        // 名字层开关 / 规则文件变化 → 跟着启停名字层，并让 IP 层句柄的 not udp 同步
                        var nameStamp = Config.ConfigStamp();     // 3.2：config.ini + 三个旧开关里最新的那个
                        var ruleStamp = File.Exists(IpEngine.RulesFile) ? File.GetLastWriteTime(IpEngine.RulesFile) : DateTime.MinValue;
                        var modeStamp = File.Exists(NameLayer.ModeFile) ? File.GetLastWriteTime(NameLayer.ModeFile) : DateTime.MinValue;
                        if (nameStamp != lastFlagStamp || ruleStamp != lastRuleStamp)
                        {
                            lastFlagStamp = nameStamp; lastRuleStamp = ruleStamp;
                            var nOnly = NameLayer.NameOnlyMode;
                            var want = NameLayer.Enabled || nOnly;
                            NameLayer.Stop();
                            if (want) Console.WriteLine("名字层配置变化，重启: " + NameLayer.Start());
                            else Console.WriteLine("名字层配置变化：已关闭。");

                            Blocker.Stop();      // 模式可能变了，IP 层句柄一律重建（纯名字模式就干脆不开）
                            if (nOnly)
                            {
                                var delegated = Blocker.Start(new List<IpEntry>());
                                errState = delegated == "OK" ? "" : delegated;
                                Console.WriteLine("拦截模式=纯名字：IP 清单不参与拦截；" + delegated);
                            }
                            else
                            {
                                var ri = Blocker.Start(IpEngine.ReadEntries(), IpEngine.ExcludeUdpForNameLayer());
                                Console.WriteLine(ri == "OK" ? "IP 层句柄已按新配置重建。" : ("IP 层重建失败: " + ri));
                            }
                            stamp = File.GetLastWriteTime(IpEngine.IpFile);
                        }

                        var st = File.GetLastWriteTime(IpEngine.IpFile);
                        if (st != stamp)
                        {
                            stamp = st;
                            if (NameLayer.NameOnlyMode)
                                Console.WriteLine("ip_block.txt 变化，但当前是纯名字模式 —— 不做任何拦截改动。");
                            else
                            {
                            Console.WriteLine("ip_block.txt 变化，重载 ...");
                            Blocker.Stop();
                            var r2 = Blocker.Start(IpEngine.ReadEntries(), IpEngine.ExcludeUdpForNameLayer());
                            if (r2 == "OK") { errState = ""; Console.WriteLine("已重载。"); }
                            else
                            {
                                errState = "ERROR: 重载失败 " + r2;
                                Console.WriteLine("重载失败: " + r2 + " —— 3 秒后重试（这期间拦截是停止的）");
                                IpEngine.WriteHeartbeat(false, errState);
                                Thread.Sleep(3000);
                                var r3 = Blocker.Start(IpEngine.ReadEntries(), IpEngine.ExcludeUdpForNameLayer());
                                Console.WriteLine(r3 == "OK" ? "重试成功，拦截已恢复。" : ("重试仍失败: " + r3));
                                errState = Blocker.IsActive ? "" : ("ERROR: 重载失败 " + r3);
                            }
                            }
                        }

                        // 每 60 秒尝试把"待解析"的服名补成 IP 拦截。
                        // V-03: 放到后台线程，扫描几十秒也不再让心跳停更（否则界面会误判"已停止"）。
                        if (DateTime.Now >= nextPending && Interlocked.CompareExchange(ref pendingBusy, 1, 0) == 0)
                        {
                            nextPending = DateTime.Now.AddSeconds(60);
                            var th = new Thread(() =>
                            {
                                try
                                {
                                    var n = IpEngine.ResolvePending(true, 5, Console.WriteLine);
                                    if (n > 0)
                                        Console.WriteLine("已把新定位到的服加入拦截（共 " + IpEngine.ReadEntries().Count +
                                                          " 条地址），常驻进程会在 5 秒内自动重载。");
                                }
                                catch (Exception ex) { Console.WriteLine("待解析处理出错: " + ex.Message); }
                                finally { Interlocked.Exchange(ref pendingBusy, 0); }
                            });
                            th.IsBackground = true;
                            th.Start();
                        }
                    }
                    Console.WriteLine("已丢弃 " + Interlocked.Read(ref Blocker.Dropped) + " 个包；名字层命中 " +
                                      Interlocked.Read(ref NameLayer.NameHits) + " 次，停止拦截。");
                    NameLayer.Stop();
                    Blocker.Stop();
                    // 「停止拦截并退出」= 两层都停；auto 配置保留，下次 --run/登录时监视进程会被重新拉起
                    if (GroupServerFilter.AutoEnabled)
                    {
                        string stopResidentReport;
                        GroupServerFilter.StopResident(out stopResidentReport);
                        Console.WriteLine(stopResidentReport);
                    }
                    IpEngine.ClearHeartbeat();
                    return 0;
                }
                if (a0 == "--layout")
                {
                    var f = new MainForm();
                    int issues = 0;
                    var fc = f.ClientRectangle;
                    Console.WriteLine("窗体客户区: " + fc.Width + " x " + fc.Height);
                    foreach (var c in Descendants(f))
                    {
                        var parent = c.Parent; if (parent == null) continue;
                        var pr = parent.ClientRectangle;
                        bool bad = c.Left < 0 || c.Top < 0 || c.Right > pr.Width || c.Bottom > pr.Height;
                        if (!bad && parent == f) bad = c.Right > fc.Width || c.Bottom > fc.Height;
                        if (bad)
                        {
                            issues++;
                            Console.WriteLine("  越界: {0,-12} \"{1}\" bounds=({2},{3},{4},{5}) 父={6} 客户区={7}x{8}",
                                c.GetType().Name, c.Text, c.Left, c.Top, c.Right, c.Bottom, parent.GetType().Name, pr.Width, pr.Height);
                        }
                    }
                    Console.WriteLine(issues == 0 ? "布局自检通过：无控件越界。" : ("布局自检失败：" + issues + " 处越界。"));
                    f.Dispose();
                    return issues == 0 ? 0 : 1;
                }
                if (a0 == "--shot")
                {
                    var path = args.Length >= 2 ? args[1] : Path.Combine(IpEngine.Root, "IpBlock-ui.png");
                    Application.EnableVisualStyles();
                    Application.SetCompatibleTextRenderingDefault(false);
                    using (var f = new MainForm())
                    {
                        f.StartPosition = FormStartPosition.Manual;
                        f.Location = new Point(-5000, -5000);
                        f.ShowInTaskbar = false;
                        f.Show();
                        for (int i = 0; i < 20; i++) { Application.DoEvents(); Thread.Sleep(25); }
                        f.Refresh(); Application.DoEvents();
                        using (var bmp = new Bitmap(f.ClientSize.Width, f.ClientSize.Height))
                        {
                            f.DrawToBitmap(bmp, new Rectangle(0, 0, bmp.Width, bmp.Height));
                            bmp.Save(path, System.Drawing.Imaging.ImageFormat.Png);
                        }
                        f.Hide();
                    }
                    Console.WriteLine("界面截图已保存: " + path);
                    return 0;
                }
                Console.WriteLine("未知参数: " + args[0] + "（用 --help）");
                return 2;
            }
            catch (Exception ex)
            {
                Console.WriteLine("错误: " + ex.Message);
                return 1;
            }
        }
    }
}
