// ============================================================================
//  Lifecycle —— 常驻拦截的进程/计划任务生命周期（唯一实现）
//  UI、RulesTool.ps1、FilterTool.exe --lifecycle 都走这里，避免多处各写一套。
// ============================================================================

using System;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;

namespace SteamServerFilterIpBlock
{
    internal static class Lifecycle
    {
        public const string TaskName       = "SteamServerFilter IP Block";
        public const string LogTaskName    = "SteamServerFilter Log Cleanup";
        public const string ExeName        = "FilterTool.exe";
        public const string LegacyTaskName = "SteamServerFilter Startup";
        public const string LegacyExeName  = "SteamServerFilter.exe";

        private static string _root;

        /// <summary>程序所在目录（安装目录）。可用 InitRoot 覆盖。</summary>
        public static string Root
        {
            get
            {
                if (!string.IsNullOrEmpty(_root)) return _root;
                try { _root = Path.GetDirectoryName(Process.GetCurrentProcess().MainModule.FileName); } catch { }
                if (string.IsNullOrEmpty(_root)) _root = AppDomain.CurrentDomain.BaseDirectory;
                return _root;
            }
            set { _root = value; }
        }

        public static void InitRoot()
        {
            _root = null;
        }

        public static string LogDir { get { return Path.Combine(Root, "Logs"); } }
        public static string LegacyArchiveDir { get { return Path.Combine(Root, "_archive", "legacy-binaries"); } }

        // ---------------------------------------------------------- 子进程
        private static Encoding ConsoleEnc()
        {
            try { return Encoding.GetEncoding(936); } catch { return Encoding.Default; }
        }

        private static bool RunOut(string file, string args, out string output)
        {
            output = "";
            try
            {
                var psi = new ProcessStartInfo(file, args)
                {
                    UseShellExecute = false,
                    CreateNoWindow = true,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    StandardOutputEncoding = ConsoleEnc(),
                    StandardErrorEncoding = ConsoleEnc()
                };
                using (var p = Process.Start(psi))
                {
                    var ob = new StringBuilder();
                    var eb = new StringBuilder();
                    p.OutputDataReceived += (s, e) => { if (e.Data != null) ob.AppendLine(e.Data); };
                    p.ErrorDataReceived += (s, e) => { if (e.Data != null) eb.AppendLine(e.Data); };
                    p.BeginOutputReadLine();
                    p.BeginErrorReadLine();
                    if (!p.WaitForExit(20000)) { try { p.Kill(); } catch { } return false; }
                    p.WaitForExit();
                    output = ob.ToString().Trim();
                    if (p.ExitCode != 0 && output.Length == 0) output = eb.ToString().Trim();
                    return p.ExitCode == 0;
                }
            }
            catch (Exception ex) { output = ex.Message; return false; }
        }

        // ---------------------------------------------------------- 计划任务
        public static bool TaskInstalled()
        {
            string o;
            return RunOut("schtasks.exe", "/Query /TN \"" + TaskName + "\"", out o);
        }

        public static bool LogTaskInstalled()
        {
            string o;
            return RunOut("schtasks.exe", "/Query /TN \"" + LogTaskName + "\"", out o);
        }

        public static bool IsLegacyTaskInstalled()
        {
            string o;
            return RunOut("schtasks.exe", "/Query /TN \"" + LegacyTaskName + "\"", out o);
        }

        /// <summary>计划任务状态文本（Running/Ready/Disabled 等，系统本地化）；查不到返回「未知」。</summary>
        public static string TaskState()
        {
            string o;
            if (!RunOut("schtasks.exe", "/Query /TN \"" + TaskName + "\" /FO CSV /NH", out o)) return TaskInstalled() ? "已安装" : "未安装";
            var line = o.Replace("\r", "").Split('\n').FirstOrDefault(l => l.Trim().Length > 0);
            if (line == null) return "未知";
            var m = Regex.Matches(line, "\"([^\"]*)\"");
            if (m.Count >= 3) return m[2].Groups[1].Value;
            return "未知";
        }

        public static string LogTaskState()
        {
            string o;
            if (!RunOut("schtasks.exe", "/Query /TN \"" + LogTaskName + "\" /FO CSV /NH", out o)) return LogTaskInstalled() ? "已安装" : "未安装";
            var line = o.Replace("\r", "").Split('\n').FirstOrDefault(l => l.Trim().Length > 0);
            if (line == null) return "未知";
            var m = Regex.Matches(line, "\"([^\"]*)\"");
            if (m.Count >= 3) return m[2].Groups[1].Value;
            return "未知";
        }

        public static bool RunTask()
        {
            string o;
            return RunOut("schtasks.exe", "/Run /TN \"" + TaskName + "\"", out o);
        }

        /// <summary>删除旧计划任务 SteamServerFilter Startup（旧入口已退役）。</summary>
        public static string DeleteLegacyTask()
        {
            string o;
            if (!IsLegacyTaskInstalled()) return "旧计划任务「" + LegacyTaskName + "」不存在（已删除）";
            bool ok = RunOut("schtasks.exe", "/Delete /TN \"" + LegacyTaskName + "\" /F", out o);
            return ok ? "已删除旧计划任务「" + LegacyTaskName + "」" : ("删除旧计划任务失败：" + o);
        }

        // ---------------------------------------------------------- 进程
        /// <summary>
        /// 常驻 FilterTool 进程；排除当前进程（CLI 自己也叫 FilterTool.exe），
        /// 并且只接受镜像路径等于「安装目录\FilterTool.exe」的进程。
        /// P1：不能仅凭进程名终止进程——同名程序可能属于其他目录/其他产品。
        /// </summary>
        public static Process[] Processes()
        {
            try
            {
                int self = Process.GetCurrentProcess().Id;
                // 组服过滤的独立监视进程也是 FilterTool.exe，但它是另一层：不能当成常驻拦截进程
                // 结束掉（否则 --lifecycle restart 会把刚拉起的监视进程当“重复进程”杀掉）。
                int resident = GroupServerFilter.ResidentProcessId();
                var allowed = new[] { Path.Combine(Root, ExeName) };
                return Process.GetProcessesByName("FilterTool")
                    .Where(p => p.Id != self && p.Id != resident && MatchesImage(p, allowed)).ToArray();
            }
            catch { return new Process[0]; }
        }

        public static Process[] LegacyProcesses()
        {
            try
            {
                var allowed = new[]
                {
                    Path.Combine(Root, LegacyExeName),
                    Path.Combine(LegacyArchiveDir, LegacyExeName)
                };
                return Process.GetProcessesByName("SteamServerFilter")
                    .Where(p => MatchesImage(p, allowed)).ToArray();
            }
            catch { return new Process[0]; }
        }

        /// <summary>镜像路径必须与允许列表中的某个绝对路径完全一致（不区分大小写）。</summary>
        internal static bool MatchesImage(Process p, string[] allowedPaths)
        {
            try
            {
                string actual = p.MainModule.FileName;
                if (string.IsNullOrEmpty(actual)) return false;
                actual = Path.GetFullPath(actual);
                foreach (var want in allowedPaths)
                {
                    if (string.IsNullOrEmpty(want)) continue;
                    if (string.Equals(actual, Path.GetFullPath(want), StringComparison.OrdinalIgnoreCase)) return true;
                }
                return false;
            }
            catch { return false; }
        }

        /// <summary>同名但镜像路径不在允许列表里的进程数（只提示，绝不终止）。</summary>
        public static int ForeignNameMatches(string processName, string[] allowedPaths)
        {
            try
            {
                int self = Process.GetCurrentProcess().Id;
                return Process.GetProcessesByName(processName)
                    .Count(p => p.Id != self && !MatchesImage(p, allowedPaths));
            }
            catch { return 0; }
        }

        // ---------------------------------------------------------- 重启
        /// <summary>结束并重新启动常驻拦截（排除自身；旧引擎进程一并清理）。</summary>
        public static string RestartLog()
        {
            var sb = new StringBuilder();
            var procs = Processes();
            if (procs.Length == 0) sb.AppendLine("过滤器当前未运行。");
            foreach (var p in procs)
            {
                try
                {
                    int pid = p.Id;
                    p.Kill();
                    p.WaitForExit(5000);
                    sb.AppendLine("已结束过滤器进程 PID " + pid + "。");
                }
                catch (Exception ex)
                {
                    sb.AppendLine("结束进程失败（需要管理员权限）：" + ex.Message);
                }
            }
            Thread.Sleep(800);

            foreach (var lp in LegacyProcesses())
            {
                try
                {
                    int pid = lp.Id;
                    lp.Kill();
                    lp.WaitForExit(4000);
                    sb.AppendLine("已结束旧引擎进程 PID " + pid + "（旧入口已归档到 _archive\\legacy-binaries）。");
                }
                catch (Exception ex) { sb.AppendLine("结束旧引擎进程失败：" + ex.Message); }
            }

            bool taskStarted = false;
            if (TaskInstalled())
            {
                if (RunTask()) { taskStarted = true; sb.AppendLine("已通过计划任务「" + TaskName + "」启动。"); }
                else sb.AppendLine("计划任务「" + TaskName + "」调用失败，尝试直接启动。");
            }
            else sb.AppendLine("没有计划任务「" + TaskName + "」，尝试直接启动。");

            if (!taskStarted)
            {
                var exe = Path.Combine(Root, ExeName);
                if (File.Exists(exe))
                {
                    try
                    {
                        Process.Start(new ProcessStartInfo(exe, "--run") { UseShellExecute = true, WorkingDirectory = Root });
                        sb.AppendLine("已直接启动 " + ExeName + " --run。");
                    }
                    catch (Exception ex) { sb.AppendLine("启动失败：" + ex.Message); }
                }
                else sb.AppendLine("找不到 " + exe + "。");
            }

            // 冷启动/计划任务慢时固定等待会误报；最多轮询 12 秒。
            var after = Processes();
            for (int i = 0; i < 24; i++)
            {
                Thread.Sleep(500);
                after = Processes();
                if (after.Length > 0) break;
            }
            after = Processes();
            if (after.Length > 1)
            {
                Process keep = null;
                DateTime keepStart = DateTime.MaxValue;
                foreach (var p2 in after)
                {
                    try { if (p2.StartTime < keepStart) { keepStart = p2.StartTime; keep = p2; } } catch { }
                }
                if (keep != null)
                {
                    foreach (var extra in after.Where(x => x.Id != keep.Id).ToArray())
                    {
                        try { int pid = extra.Id; extra.Kill(); extra.WaitForExit(4000); sb.AppendLine("已结束重复的过滤器进程 PID " + pid + "。"); } catch { }
                    }
                    after = Processes();
                }
            }
            if (after.Length > 0)
                sb.AppendLine("过滤器已重新运行：PID " + string.Join(", ", after.Select(p => p.Id.ToString()).ToArray()));
            else
            {
                sb.AppendLine("过滤器似乎没起来。请右键本工具「以管理员身份运行」后重试，");
                sb.AppendLine("或到过滤器托盘的右键菜单点「重载规则」。");
            }

            var startup = LastStartupInfo();
            if (startup != null) sb.AppendLine(startup);
            return sb.ToString().TrimEnd();
        }

        public static string LastStartupInfo()
        {
            try
            {
                var today = Path.Combine(LogDir, DateTime.Now.ToString("yyyy-MM-dd") + ".log");
                if (!File.Exists(today)) return null;
                string text;
                using (var fs = new FileStream(today, FileMode.Open, FileAccess.Read, FileShare.ReadWrite))
                using (var sr = new StreamReader(fs, Encoding.UTF8, true))
                    text = sr.ReadToEnd();
                var lines = text.Replace("\r\n", "\n").Replace('\r', '\n').Split('\n');
                var hits = lines.Where(l => l.Contains("rules have been read") || l.Contains("Program starts")).ToArray();
                if (hits.Length == 0) return null;
                if (hits.Length == 1) return "程序日志：" + hits[0].Trim();
                return "程序日志：" + hits[hits.Length - 2].Trim() + " | " + hits[hits.Length - 1].Trim();
            }
            catch { return null; }
        }

        // ---------------------------------------------------------- CLI
        public static int CliStatus(Action<string> log)
        {
            log("常驻拦截（" + ExeName + "）");
            log("  目录: " + Root);
            var procs = Processes();
            if (procs.Length > 0)
            {
                foreach (var p in procs)
                {
                    string started = "";
                    try { started = "  启动于 " + p.StartTime.ToString("yyyy-MM-dd HH:mm:ss"); } catch { }
                    log("  运行中: PID " + p.Id + started);
                }
            }
            else log("  未运行");
            if (procs.Length > 1)
                log("  [WARN] 同时有 " + procs.Length + " 个常驻进程（重复启动会抢 WinDivert），执行 --lifecycle restart 可清理为一个。");
            int foreign = ForeignNameMatches("FilterTool", new[] { Path.Combine(Root, ExeName) });
            if (foreign > 0)
                log("  [WARN] 忽略 " + foreign + " 个同名但镜像路径不在安装目录的 FilterTool 进程（不会终止它们）。");

            var legacy = LegacyProcesses();
            if (legacy.Length > 0)
                log("  警告: 旧引擎 " + LegacyExeName + " 仍在运行（PID " + string.Join(", ", legacy.Select(p => p.Id.ToString()).ToArray()) + "），请结束它（可能与 FilterTool 抢 WinDivert）");

            log("计划任务");
            log("  " + TaskName + ": " + (TaskInstalled() ? TaskState() : "未安装"));
            log("  " + LogTaskName + ": " + (LogTaskInstalled() ? LogTaskState() : "未安装"));
            log("  " + LegacyTaskName + ": " + (IsLegacyTaskInstalled() ? "仍存在（旧入口已退役，建议 FilterTool.exe --lifecycle delete-legacy）" : "不存在（已删除）"));

            if (Directory.Exists(LegacyArchiveDir))
                log("旧入口归档: " + LegacyArchiveDir);
            var startup = LastStartupInfo();
            if (startup != null) log(startup);
            return 0;
        }

        public static int CliRestart(Action<string> log)
        {
            log(RestartLog());
            return Processes().Length > 0 ? 0 : 1;
        }

        public static int CliDeleteLegacy(Action<string> log)
        {
            log(DeleteLegacyTask());
            int killed = 0;
            foreach (var p in LegacyProcesses())
            {
                try { p.Kill(); p.WaitForExit(4000); killed++; } catch { }
            }
            log("已结束旧引擎进程 " + killed + " 个");
            if (Directory.Exists(LegacyArchiveDir)) log("旧二进制归档（保留，勿运行）: " + LegacyArchiveDir);
            else log("旧二进制归档目录不存在: " + LegacyArchiveDir);
            return 0;
        }
    }
}
