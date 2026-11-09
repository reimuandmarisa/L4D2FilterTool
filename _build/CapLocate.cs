// ============================================================================
//  CapLocate —— 抓包定位：找出某个服名对应的真实 IP
//
//  为什么需要：名字↔IP 的对应关系只能"观测"到。有些服（例如"纯天然"）
//  既没被过滤器拦过、也没出现在任何已知 endpoint 里，主动扫描就找不到。
//  这时唯一的办法是：本机刷新一次服务器浏览器，把当时的 A2S 报文抓下来，
//  直接从报文里读出"服名 + 来源 IP"。
//
//  实现：pktmon（Windows 自带，只读抓包，不改包、不影响流量）
//        → etl2pcap → 自己解析 pcapng + IPv4/UDP + A2S_INFO 应答
//        → 保留应答原名与来源端点，按 Name + endpoint 聚合计数。
//        不主动查询网络，不写映射/规则；不支持分片，临时文件在 finally 清理。
// ============================================================================

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Text;
using System.Threading;

namespace SteamServerFilterIpBlock
{
    internal sealed class A2sHit
    {
        public string Name = "";
        public string Ip = "";
        public int Port;
    }

    internal sealed class A2sCandidate
    {
        public string Name = "";
        public string Ip = "";
        public int Port;
        public int Count;
        public string Endpoint { get { return (Ip.IndexOf(':') >= 0 ? "[" + Ip + "]" : Ip) + ":" + Port; } }
        public string Source { get { return "A2S应答"; } }
    }

    internal static class CapLocate
    {
        private static string WorkDir { get { return Path.Combine(IpEngine.Root, "_work"); } }

        private static string Run(string file, string args, int timeoutMs = 60000, CancellationToken cancellationToken = default(CancellationToken), bool finishControlCommand = false)
        {
            try
            {
                var psi = new ProcessStartInfo(file, args)
                {
                    UseShellExecute = false,
                    CreateNoWindow = true,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true
                };
                using (var p = Process.Start(psi))
                {
                    // 先异步消费两个管道，避免子进程输出过多时互相等待。
                    var ob = new StringBuilder();
                    var eb = new StringBuilder();
                    p.OutputDataReceived += (s, e) => { if (e.Data != null) ob.AppendLine(e.Data); };
                    p.ErrorDataReceived += (s, e) => { if (e.Data != null) eb.AppendLine(e.Data); };
                    p.BeginOutputReadLine();
                    p.BeginErrorReadLine();
                    var sw = Stopwatch.StartNew();
                    while (!p.WaitForExit(200))
                    {
                        if (cancellationToken.IsCancellationRequested && !finishControlCommand)
                        {
                            try { p.Kill(); } catch { }
                            try { p.WaitForExit(200); } catch { }
                            return "CANCELLED";
                        }
                        if (sw.ElapsedMilliseconds >= timeoutMs)
                        {
                            try { p.Kill(); } catch { }
                            return "TIMEOUT";
                        }
                    }
                    p.WaitForExit();
                    var o = ob.ToString().Trim();
                    if (p.ExitCode != 0 && o.Length == 0) o = eb.ToString().Trim();
                    return p.ExitCode == 0 ? ("OK " + o) : ("FAIL(" + p.ExitCode + ") " + o);
                }
            }
            catch (Exception ex) { return "ERROR " + ex.Message; }
        }

        private static int _captureActive;
        private const string CaptureMutexName = @"Global\SteamServerFilter.CapLocate.Capture";

        /// <summary>旧调用兼容；seconds 秒内请刷新一次服务器浏览器。</summary>
        public static List<A2sHit> Capture(int seconds, Action<string> log)
        {
            return Capture(seconds, log, CancellationToken.None);
        }

        /// <summary>被动抓包；取消抛 OperationCanceledException，已有会话/并行调用抛 InvalidOperationException。</summary>
        public static List<A2sHit> Capture(int seconds, Action<string> log, CancellationToken cancellationToken)
        {
            if (seconds <= 0) throw new ArgumentOutOfRangeException("seconds", "抓包时长必须大于零。");
            cancellationToken.ThrowIfCancellationRequested();
            // Mutex 对同线程可重入，另加进程内非阻塞门，防止日志回调重入 Capture。
            if (Interlocked.CompareExchange(ref _captureActive, 1, 0) != 0)
                throw new InvalidOperationException("本软件已有 Capture 正在执行，请等待结束或取消后再试。");

            Mutex mutex = null;
            bool ownsMutex = false, started = false, filterAttempted = false;
            string etlPath = null, pcapPath = null, filterName = null;
            try
            {
                mutex = new Mutex(false, CaptureMutexName);
                try { ownsMutex = mutex.WaitOne(0); }
                catch (AbandonedMutexException) { ownsMutex = true; }
                if (!ownsMutex)
                    throw new InvalidOperationException("另一个本软件进程已有 Capture 正在执行，请等待结束或取消后再试。");

                cancellationToken.ThrowIfCancellationRequested();
                if (log != null) log("· 正在检查 pktmon 状态；已有会话时不会停止或接管。");
                var status = Run("pktmon.exe", "status", 15000, cancellationToken);
                cancellationToken.ThrowIfCancellationRequested();
                RequireIdle(status);

                var session = Guid.NewGuid().ToString("N");
                filterName = "SSF_" + session;
                etlPath = Path.Combine(WorkDir, "locate-" + session + ".etl");
                pcapPath = Path.Combine(WorkDir, "locate-" + session + ".pcapng");
                Directory.CreateDirectory(WorkDir);
                cancellationToken.ThrowIfCancellationRequested();

                // 控制命令必须取得明确退出结果才能确认所有权；期间只记录取消，随后立即处理。
                filterAttempted = true;
                var f = Run("pktmon.exe", "filter add " + filterName + " -t UDP", 15000, cancellationToken, true);
                cancellationToken.ThrowIfCancellationRequested();
                if (!f.StartsWith("OK ", StringComparison.Ordinal))
                    throw new InvalidOperationException("添加本次 UDP 过滤器失败：" + f);
                if (log != null) log("· 已添加本次 UDP 过滤器：" + filterName);
                cancellationToken.ThrowIfCancellationRequested();

                var st = Run("pktmon.exe", "start --capture --pkt-size 700 --file-name \"" + etlPath + "\" --file-size 64", 15000, cancellationToken, true);
                started = st.StartsWith("OK ", StringComparison.Ordinal);
                cancellationToken.ThrowIfCancellationRequested();
                if (!started) throw new InvalidOperationException("抓包启动失败（未取得本次会话所有权，不会执行 stop）：" + st);
                if (log != null) log("· 抓包中，共 " + seconds + " 秒；请现在去 L4D2 刷新一次服务器浏览器。可取消。");

                var clock = Stopwatch.StartNew();
                long duration = (long)seconds * 1000;
                int lastLeft = -1;
                while (clock.ElapsedMilliseconds < duration)
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    int left = (int)((duration - clock.ElapsedMilliseconds + 999) / 1000);
                    if (left != lastLeft)
                    {
                        if (log != null) log("   还剩 " + left + " 秒 ...");
                        lastLeft = left;
                    }
                    int wait = (int)Math.Min(200, Math.Max(1, duration - clock.ElapsedMilliseconds));
                    if (cancellationToken.WaitHandle.WaitOne(wait)) cancellationToken.ThrowIfCancellationRequested();
                }
                cancellationToken.ThrowIfCancellationRequested();
                var stop = Run("pktmon.exe", "stop", 15000, cancellationToken, true);
                if (stop.StartsWith("OK ", StringComparison.Ordinal)) started = false;
                cancellationToken.ThrowIfCancellationRequested();
                if (started) throw new InvalidOperationException("停止本次抓包失败：" + stop);

                long size = File.Exists(etlPath) ? new FileInfo(etlPath).Length : 0;
                if (log != null) log("· 抓包结束，原始大小 " + (size / 1024) + " KB，正在转换 ...");
                cancellationToken.ThrowIfCancellationRequested();
                if (size == 0)
                {
                    if (log != null) log("× 没抓到任何数据，请确认刷新了服务器浏览器。");
                    return new List<A2sHit>();
                }

                // 转换无全局状态，可在取消时结束转换进程；转换前后均检查取消。
                cancellationToken.ThrowIfCancellationRequested();
                var cv = Run("pktmon.exe", "etl2pcap \"" + etlPath + "\" --out \"" + pcapPath + "\"", 180000, cancellationToken);
                cancellationToken.ThrowIfCancellationRequested();
                if (!cv.StartsWith("OK ", StringComparison.Ordinal) || !File.Exists(pcapPath))
                    throw new InvalidOperationException("抓包文件转换失败：" + cv);
                var hits = ParseA2s(pcapPath, log, cancellationToken);
                cancellationToken.ThrowIfCancellationRequested();
                if (log != null) log("· 解析完成：拿到 " + hits.Count + " 个普通 A2S_INFO 应答，将清理本次临时文件。");
                cancellationToken.ThrowIfCancellationRequested();
                return hits;
            }
            catch (OperationCanceledException)
            {
                CleanupLog(log, "· 抓包定位已取消，正在清理本次会话与临时文件。");
                throw;
            }
            finally
            {
                try
                {
                    // 不使用取消令牌跳过清理；只有本次明确成功 start 才有权 stop。
                    if (started)
                    {
                        var stop = Run("pktmon.exe", "stop", 15000, CancellationToken.None, true);
                        if (!stop.StartsWith("OK ", StringComparison.Ordinal)) CleanupLog(log, "× 本次会话停止失败：" + stop);
                    }
                    if (filterAttempted)
                    {
                        var removed = Run("pktmon.exe", "filter remove " + filterName, 15000);
                        if (!removed.StartsWith("OK ", StringComparison.Ordinal)) CleanupLog(log, "× 本次过滤器清理失败：" + removed);
                    }
                    DeleteTemporary(etlPath, log);
                    DeleteTemporary(pcapPath, log);
                }
                finally
                {
                    try { if (ownsMutex) mutex.ReleaseMutex(); }
                    finally
                    {
                        if (mutex != null) mutex.Dispose();
                        Interlocked.Exchange(ref _captureActive, 0);
                    }
                }
            }
        }

        private static void RequireIdle(string status)
        {
            if (!status.StartsWith("OK ", StringComparison.Ordinal))
                throw new InvalidOperationException("无法检查 pktmon 状态，已放弃抓包：" + status);
            string text = status.Substring(3).Trim().TrimEnd('.', '。').ToLowerInvariant();
            // 只接受明确的空闲状态；未知语言/版本的输出也不冒险接管系统会话。
            if (text == "packet monitor is not running" || text == "pktmon is not running" ||
                text == "packet monitor is stopped" || text == "pktmon is stopped" ||
                text == "数据包监视器未运行" || text == "数据包监视器未在运行" ||
                text == "数据包监视器没有运行" || text == "数据包监视器已停止" ||
                text == "数据包监视器未启动") return;
            throw new InvalidOperationException("pktmon 已有运行会话，或状态无法确认为空闲；不会停止他人的会话。status：" + status);
        }

        private static void CleanupLog(Action<string> log, string message)
        {
            // 用户日志回调异常不能阻断 finally 中后续资源清理。
            try { if (log != null) log(message); } catch { }
        }

        private static void DeleteTemporary(string path, Action<string> log)
        {
            if (path == null) return;
            try { if (File.Exists(path)) File.Delete(path); }
            catch (Exception ex) { CleanupLog(log, "× 本次临时文件删除失败（" + path + "）：" + ex.Message); }
        }

        /// <summary>仅按应答原始 Name + 校验后的 endpoint 聚合；不接受或匹配输入 display。</summary>
        public static List<A2sCandidate> AggregateHits(IEnumerable<A2sHit> hits)
        {
            var result = new List<A2sCandidate>();
            var names = new Dictionary<string, Dictionary<string, A2sCandidate>>(StringComparer.Ordinal);
            if (hits == null) return result;
            foreach (var hit in hits)
            {
                IPAddress address;
                if (hit == null || string.IsNullOrWhiteSpace(hit.Name) || hit.Port < 1 || hit.Port > 65535 ||
                    !IPAddress.TryParse(hit.Ip, out address)) continue;
                // IPAddress.TryParse 接受十进制整型/短 IPv4；候选仅允许正常点分 IPv4 或 IPv6。
                if (address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
                {
                    var parts = hit.Ip.Split('.');
                    if (parts.Length != 4 || parts.Any(part => part.Length == 0 || part.Length > 3 ||
                        part.Any(ch => ch < '0' || ch > '9'))) continue;
                }
                var ip = address.ToString();
                var endpoint = (ip.IndexOf(':') >= 0 ? "[" + ip + "]" : ip) + ":" + hit.Port;
                Dictionary<string, A2sCandidate> endpoints;
                if (!names.TryGetValue(hit.Name, out endpoints))
                {
                    endpoints = new Dictionary<string, A2sCandidate>(StringComparer.Ordinal);
                    names.Add(hit.Name, endpoints);
                }
                A2sCandidate candidate;
                if (endpoints.TryGetValue(endpoint, out candidate)) candidate.Count++;
                else
                {
                    candidate = new A2sCandidate { Name = hit.Name, Ip = ip, Port = hit.Port, Count = 1 };
                    endpoints.Add(endpoint, candidate);
                    result.Add(candidate);
                }
            }
            return result;
        }

        // ---------------------------------------------------------- pcapng 解析
        private static readonly byte[] SHB = { 0x0A, 0x0D, 0x0D, 0x0A };

        // P1：抓包文件是外部输入，必须有硬上限；块数量/结果条数同样设上限，
        // 防止畸形或超大文件把内存/CPU 拉满（TopPeers 与 ParseA2s 共用）。
        private const long MaxCaptureBytes = 256L * 1024 * 1024;
        private const int MaxCaptureBlocks = 2000000;
        private const int MaxA2sHits = 200000;
        private const int MaxPeerEntries = 100000;

        /// <summary>读取抓包文件（有大小上限）；失败时给出可读原因。</summary>
        private static bool TryReadCapture(string path, out byte[] data, out string error)
        {
            data = null;
            error = "";
            try
            {
                var info = new FileInfo(path);
                if (!info.Exists) { error = "文件不存在。"; return false; }
                if (info.Length <= 0) { error = "文件为空。"; return false; }
                if (info.Length > MaxCaptureBytes)
                {
                    error = "抓包文件 " + (info.Length / (1024 * 1024)) + " MB 超过 " + (MaxCaptureBytes / (1024 * 1024)) + " MB 上限，已拒绝解析（请先裁剪）。";
                    return false;
                }
                data = File.ReadAllBytes(path);
                return true;
            }
            catch (Exception ex)
            {
                error = "读取失败：" + ex.Message;
                return false;
            }
        }

        /// <summary>pcapng 块级结构校验（与 ParseA2s 完全一致，供 TopPeers 复用）。</summary>
        private static bool IsValidBlock(byte[] data, int i, uint total, char endian)
        {
            if (total < 12 || (total & 3) != 0) return false;
            if (total > data.Length - i) return false;
            return ReadU32(data, i + (int)total - 4, endian) == total;
        }

        public static List<A2sHit> ParseFile(string path, Action<string> log) { return ParseA2s(path, log); }

        /// <summary>统计 UDP 通信对端（包数最多的在前）。
        /// 用途：人正在某个服里玩时，即使没有 A2S 查询，也能从流量里认出那台服的 IP。</summary>
        public static List<KeyValuePair<string, int>> TopPeers(string path, int topN = 25)
        {
            var count = new Dictionary<string, int>(StringComparer.Ordinal);
            byte[] data;
            string readError;
            if (!TryReadCapture(path, out data, out readError)) return new List<KeyValuePair<string, int>>();
            if (topN <= 0) return new List<KeyValuePair<string, int>>();
            char endian = '<';
            var linkTypes = new List<int>();
            int i = 0, blocks = 0;
            while (i + 12 <= data.Length)
            {
                if (++blocks > MaxCaptureBlocks) break;
                if (data[i] == SHB[0] && data[i + 1] == SHB[1] && data[i + 2] == SHB[2] && data[i + 3] == SHB[3])
                {
                    uint bom = BitConverter.ToUInt32(data, i + 8);
                    if (bom == 0x1A2B3C4DU) endian = '<';
                    else if (bom == 0x4D3C2B1AU) endian = '>';
                    else break;
                    uint tot = ReadU32(data, i + 4, endian);
                    if (tot < 28 || !IsValidBlock(data, i, tot, endian)) break;
                    linkTypes.Clear();
                    i += (int)tot;
                    continue;
                }
                uint type = ReadU32(data, i, endian);
                uint total = ReadU32(data, i + 4, endian);
                if (!IsValidBlock(data, i, total, endian)) break;
                if (type == 1 && total >= 20) linkTypes.Add((int)ReadU16(data, i + 8, endian));
                else if (type == 6 && total >= 32)
                {
                    uint iface = ReadU32(data, i + 8, endian);
                    uint caplen = ReadU32(data, i + 20, endian);
                    int off = i + 28;
                    if (caplen > 0 && caplen <= total - 32 && iface < linkTypes.Count)
                    {
                        int lt = linkTypes[(int)iface];
                        foreach (var ep in UdpPeers(data, off, (int)caplen, lt))
                        {
                            int c;
                            count[ep] = count.TryGetValue(ep, out c) ? c + 1 : 1;
                        }
                        if (count.Count > MaxPeerEntries) break;
                    }
                }
                i += (int)total;
            }
            return count.OrderByDescending(kv => kv.Value).Take(topN).ToList();
        }

        // V-26: 补齐 CGNAT(100.64/10)、benchmark(198.18/15)、保留段(0/8, 192.0.2/24, 203.0.113/24)
        private static bool IsPrivate(string ip)
        {
            var p = ip.Split('.');
            if (p.Length != 4) return true;
            int a, b, c;
            if (!int.TryParse(p[0], out a) || !int.TryParse(p[1], out b) || !int.TryParse(p[2], out c)) return true;
            if (a == 0 || a == 10 || a == 127) return true;
            if (a == 100 && b >= 64 && b <= 127) return true;              // CGNAT 100.64.0.0/10
            if (a == 169 && b == 254) return true;
            if (a == 172 && b >= 16 && b <= 31) return true;
            if (a == 192 && b == 168) return true;
            if (a == 192 && b == 0 && c == 2) return true;                 // TEST-NET-1
            if (a == 198 && (b == 18 || b == 19)) return true;             // benchmark 198.18.0.0/15
            if (a == 198 && b == 51 && c == 100) return true;
            if (a == 203 && b == 0 && c == 113) return true;
            if (a == 224 || a >= 240) return true;
            return false;
        }

        /// <summary>取包里"远端对端"的 IP:端口（可能有两个，见 V-26）。</summary>
        private static string[] UdpPeers(byte[] b, int off, int len, int linkType)
        {
            int p = off, end = off + len;
            if (linkType == 1)
            {
                if (p + 14 > end) return new string[0];
                int et = (b[p + 12] << 8) | b[p + 13];
                p += 14;
                while (et == 0x8100 || et == 0x88A8)
                {
                    if (p + 4 > end) return new string[0];
                    et = (b[p + 2] << 8) | b[p + 3];
                    p += 4;
                }
                if (et != 0x0800) return new string[0];
            }
            else if (linkType != 101 && linkType != 228) return new string[0];
            if (p + 20 > end) return new string[0];
            if ((b[p] >> 4) != 4 || b[p + 9] != 17) return new string[0];
            int ihl = (b[p] & 0x0F) * 4;
            if (ihl < 20 || p + ihl + 8 > end) return new string[0];
            var src = b[p + 12] + "." + b[p + 13] + "." + b[p + 14] + "." + b[p + 15];
            var dst = b[p + 16] + "." + b[p + 17] + "." + b[p + 18] + "." + b[p + 19];
            int u = p + ihl;
            int sport = (b[u] << 8) | b[u + 1];
            int dport = (b[u + 2] << 8) | b[u + 3];
            bool sp = IsPrivate(src), dp = IsPrivate(dst);
            if (sp && dp) return new string[0];
            if (sp) return new[] { dst + ":" + dport };
            if (dp) return new[] { src + ":" + sport };
            // V-26: 两端都是公网（无 NAT 直连 / VPN 出口）时不再直接丢弃，
            // 两个方向都交给调用方统计，避免漏掉真实对端。
            return new[] { dst + ":" + dport, src + ":" + sport };
        }

        private static List<A2sHit> ParseA2s(string path, Action<string> log, CancellationToken cancellationToken = default(CancellationToken))
        {
            var outp = new List<A2sHit>();
            byte[] data;
            string readError;
            try
            {
                cancellationToken.ThrowIfCancellationRequested();
                if (!TryReadCapture(path, out data, out readError))
                {
                    if (log != null) log("× " + readError);
                    return outp;
                }
                cancellationToken.ThrowIfCancellationRequested();
            }
            catch (OperationCanceledException) { throw; }

            char endian = '<';
            var linkTypes = new List<int>();
            int i = 0, packets = 0, a2s = 0, blocks = 0;
            bool capped = false;
            while (i <= data.Length - 12)
            {
                cancellationToken.ThrowIfCancellationRequested();
                if (++blocks > MaxCaptureBlocks) { capped = true; break; }
                if (data[i] == SHB[0] && data[i + 1] == SHB[1] && data[i + 2] == SHB[2] && data[i + 3] == SHB[3])
                {
                    uint bom = BitConverter.ToUInt32(data, i + 8);
                    if (bom == 0x1A2B3C4DU) endian = '<';
                    else if (bom == 0x4D3C2B1AU) endian = '>';
                    else break;
                    uint tot = ReadU32(data, i + 4, endian);
                    if (tot < 28 || !IsValidBlock(data, i, tot, endian)) break;
                    linkTypes.Clear();
                    i += (int)tot;
                    continue;
                }
                uint type = ReadU32(data, i, endian);
                uint total = ReadU32(data, i + 4, endian);
                if (!IsValidBlock(data, i, total, endian)) break;

                if (type == 1 && total >= 20)   // Interface Description Block
                {
                    linkTypes.Add((int)ReadU16(data, i + 8, endian));
                }
                else if (type == 6 && total >= 32)   // Enhanced Packet Block
                {
                    uint iface = ReadU32(data, i + 8, endian);
                    uint caplen = ReadU32(data, i + 20, endian);
                    int off = i + 28;
                    if (caplen > 0 && caplen <= total - 32 && iface < linkTypes.Count)
                    {
                        int lt = linkTypes[(int)iface];
                        packets++;
                        if (outp.Count >= MaxA2sHits) { capped = true; break; }
                        var hit = TryParsePacket(data, off, (int)caplen, lt);
                        // 保留原始观测次数，去重和 Count 由 AggregateHits 负责。
                        if (hit != null) { a2s++; outp.Add(hit); }
                    }
                }
                i += (int)total;
            }
            if (capped && log != null) log("   已达解析上限（块 " + MaxCaptureBlocks + " / A2S 结果 " + MaxA2sHits + "），后续数据被忽略。");
            cancellationToken.ThrowIfCancellationRequested();
            if (log != null) log("   pcapng: 解析 " + packets + " 个包，其中普通 A2S_INFO 应答 " + a2s + " 个（不解析分片）。");
            return outp;
        }

        private static uint ReadU32(byte[] b, int o, char e)
        {
            return e == '<'
                ? (uint)(b[o] | (b[o + 1] << 8) | (b[o + 2] << 16) | (b[o + 3] << 24))
                : (uint)(b[o + 3] | (b[o + 2] << 8) | (b[o + 1] << 16) | (b[o] << 24));
        }
        private static int ReadU16(byte[] b, int o, char e)
        {
            return e == '<' ? (b[o] | (b[o + 1] << 8)) : (b[o + 1] | (b[o] << 8));
        }

        /// <summary>从单个包里取出 A2S_INFO 应答的 服名 + 来源 IP:端口。</summary>
        private static A2sHit TryParsePacket(byte[] b, int off, int len, int linkType)
        {
            if (b == null || off < 0 || len < 0 || off > b.Length - len) return null;
            int p = off;
            int end = off + len;
            if (linkType == 1)          // Ethernet
            {
                if (p + 14 > end) return null;
                int et = (b[p + 12] << 8) | b[p + 13];
                p += 14;
                while (et == 0x8100 || et == 0x88A8)   // VLAN
                {
                    if (p + 4 > end) return null;
                    et = (b[p + 2] << 8) | b[p + 3];
                    p += 4;
                }
                if (et != 0x0800) return null;
            }
            else if (linkType != 101 && linkType != 228) return null;

            if (p + 20 > end) return null;
            if ((b[p] >> 4) != 4) return null;
            int ihl = (b[p] & 0x0F) * 4;
            if (ihl < 20 || b[p + 9] != 17) return null;
            int ipLength = (b[p + 2] << 8) | b[p + 3];
            if (ipLength < ihl + 8) return null;
            // 不重组 IPv4 分片，也不把填充字节当作 UDP 数据。
            if ((((b[p + 6] << 8) | b[p + 7]) & 0x3FFF) != 0) return null;
            end = Math.Min(end, p + ipLength);
            if (p + ihl + 8 > end) return null;

            var src = b[p + 12] + "." + b[p + 13] + "." + b[p + 14] + "." + b[p + 15];
            int u = p + ihl;
            int sport = (b[u] << 8) | b[u + 1];
            int ulen = (b[u + 4] << 8) | b[u + 5];
            int plen = ulen - 8;
            if (plen <= 0) return null;
            int po = u + 8;
            if (po + plen > end) plen = end - po;
            if (plen < 7) return null;
            if (b[po] != 0xFF || b[po + 1] != 0xFF || b[po + 2] != 0xFF || b[po + 3] != 0xFF) return null;
            // 仅解析普通 A2S_INFO 应答；FEFFFFFF 分片应答明确不支持。
            if (b[po + 4] != (byte)'I') return null;

            int body = po;
            if (body + 7 > po + plen || b[body + 4] != (byte)'I') return null;
            int e2 = -1;
            for (int k = body + 6; k < po + plen; k++) if (b[k] == 0) { e2 = k; break; }
            if (e2 <= body + 6) return null;
            var name = Encoding.UTF8.GetString(b, body + 6, e2 - (body + 6));
            if (name.Trim().Length == 0) return null;
            return new A2sHit { Name = name, Ip = src, Port = sport };
        }

        /// <summary>用子串/关键词在抓到的应答里找目标服。</summary>
        public static List<A2sHit> Match(List<A2sHit> hits, string target)
        {
            var t = (target ?? "").Trim();
            if (t.Length == 0) return new List<A2sHit>();
            var exact = hits.Where(h => string.Equals(h.Name, t, StringComparison.OrdinalIgnoreCase)).ToList();
            if (exact.Count > 0) return exact;
            var contains = hits.Where(h => h.Name.IndexOf(t, StringComparison.OrdinalIgnoreCase) >= 0).ToList();
            if (contains.Count > 0) return contains;
            // 关键词兜底：挑目标里"在抓到的名字中出现次数最少"的片段
            var toks = Tokenize(t);
            if (toks.Count == 0) return new List<A2sHit>();
            var freq = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
            foreach (var h in hits)
                foreach (var tk in Tokenize(h.Name))
                {
                    int c; freq[tk] = freq.TryGetValue(tk, out c) ? c + 1 : 1;
                }
            string best = null; int bestC = int.MaxValue;
            foreach (var tk in toks) { int c; if (freq.TryGetValue(tk, out c) && c < bestC) { bestC = c; best = tk; } }
            if (best == null) return new List<A2sHit>();
            var kw = hits.Where(h => h.Name.IndexOf(best, StringComparison.OrdinalIgnoreCase) >= 0).ToList();
            // V-28: 与 ResolveIps 一致做"支持度过滤" —— 搜索片段过泛时，
            //       只被 1 个服名支持的 IP 多半是无关服，直接丢掉，避免一次误拦一大片。
            var support = new Dictionary<string, int>(StringComparer.Ordinal);
            int sn = 0;
            foreach (var h in kw)
            {
                int c; support[h.Ip] = support.TryGetValue(h.Ip, out c) ? c + 1 : 1;
                sn++;
            }
            if (sn > 5)
            {
                var drop = new HashSet<string>(support.Where(kv => kv.Value < 2).Select(kv => kv.Key), StringComparer.Ordinal);
                if (drop.Count > 0) kw = kw.Where(h => !drop.Contains(h.Ip)).ToList();
            }
            return kw;
        }

        private static List<string> Tokenize(string s)
        {
            var outp = new List<string>();
            var cur = new StringBuilder();
            int mode = 0;
            Action flush = () =>
            {
                var t = cur.ToString(); cur.Length = 0;
                if (t.Length < 2) return;
                bool allDigit = true;
                foreach (var ch in t) if (!char.IsDigit(ch)) { allDigit = false; break; }
                if (allDigit) return;
                var low = t.ToLowerInvariant();
                if (!outp.Contains(low)) outp.Add(low);
            };
            foreach (var ch in s)
            {
                bool cjk = (ch >= 0x4E00 && ch <= 0x9FFF) || (ch >= 0x3400 && ch <= 0x4DBF);
                int m = cjk ? 2 : (char.IsLetterOrDigit(ch) ? 1 : 0);
                if (m == 0) { flush(); mode = 0; continue; }
                if (mode != 0 && m != mode) flush();
                mode = m;
                cur.Append(ch);
            }
            flush();
            return outp;
        }
    }
}
