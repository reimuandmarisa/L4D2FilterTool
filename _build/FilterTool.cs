// ============================================================================
//  FilterTool —— SteamServerFilter 拦截工具（统一入口）
//
//  界面：UnifiedForm（单一窗口，不分页）—— 见 Unified.cs
//  两层引擎：
//    名字层  SteamServerFilterRules.Engine      （block_rules.txt，由过滤器读取）
//    IP 层   SteamServerFilterIpBlock.Blaster/IpEngine（WinDivert 内核层丢包）
//
//  编译： csc /target:winexe /platform:x86 /win32manifest:IpBlock.manifest /win32icon:FilterTool.ico /resource:FilterTool.ico,FilterTool.ico
//              SafeFile.cs Config.cs BuildStamp.cs RulesAdd.cs IpBlock.cs NameLayer.cs TrayHost.cs AppIcon.cs CapLocate.cs GroupListDiagnostics.cs GroupServerFilter.cs SelfTest.cs Lifecycle.cs Unified.cs FilterTool.cs
// ============================================================================

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Drawing;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using System.Windows.Forms;

namespace SteamServerFilterTool
{
    internal static class Entry
    {
        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool AttachConsole(int dwProcessId);

        [STAThread]
        private static int Main(string[] args)
        {
            SteamServerFilterRules.Program.InitRoot();
            SteamServerFilterIpBlock.Program.InitRoot();
            SteamServerFilterRules.IpBridge.Root = SteamServerFilterRules.Engine.Root;

            // 规则只有一份统一文件（rules-profiles\custom.txt）：首次运行/升级时做一次幂等迁移，
            // 旧的多档位规则文件与 group_filter_rules.txt 会被归档。GUI/CLI 两条路径都先经过这里。
            try { SteamServerFilterRules.Engine.EnsureUnifiedRules(); } catch { }

            // V-09: 整个命令行路径统一兜底 —— winexe 没有控制台，未处理异常会让进程"无声消失"
            if (args.Length > 0)
            {
                try { return RunCli(args); }
                catch (Exception ex)
                {
                    try
                    {
                        BindConsole();
                        Console.WriteLine("错误: " + ex.Message);
                        Console.WriteLine(ex.StackTrace);
                    }
                    catch { }
                    return 1;
                }
            }

            Application.EnableVisualStyles();
            Application.SetCompatibleTextRenderingDefault(false);
            Application.Run(new UnifiedForm(true));
            return 0;
        }

        [DllImport("kernel32.dll")]
        private static extern IntPtr GetStdHandle(int nStdHandle);

        [DllImport("kernel32.dll")]
        private static extern IntPtr GetCurrentProcess();

        [DllImport("kernel32.dll")]
        private static extern bool TerminateProcess(IntPtr hProcess, uint uExitCode);

        // 自检进程打印完结果后直接硬退出：WinForms 窗口销毁阶段遇到第三方输入法/钩子时，
        // 约 10% 概率以 0xC000041D（用户回调里未处理异常）收尾，进程退出码被改写成崩溃码，
        // 让 build 门禁与 CI 偶发变红。TerminateProcess 不做清理，但能保证退出码就是自检结论。
        private static void HardExit(int code)
        {
            try { Console.Out.Flush(); } catch { }
            try { TerminateProcess(GetCurrentProcess(), unchecked((uint)code)); } catch { }
            Environment.Exit(code);
        }

        private static void BindConsole()
        {
            // winexe 默认没有控制台，但被 cmd/PowerShell/CI 重定向或管道捕获时 stdout 句柄是有效的。
            // 关键：先取句柄再决定是否 AttachConsole（AttachConsole 会把标准句柄换成控制台的，
            // 之后 OpenStandardOutput 就写不到调用方的管道里了，测试脚本会读不到任何输出）。
            try
            {
                var h = GetStdHandle(-11); // STD_OUTPUT_HANDLE
                if (h == IntPtr.Zero || h == new IntPtr(-1))
                {
                    try { AttachConsole(-1); } catch { }
                    h = GetStdHandle(-11);
                }
                if (h == IntPtr.Zero || h == new IntPtr(-1)) return;
                var fs = new FileStream(new Microsoft.Win32.SafeHandles.SafeFileHandle(h, false), FileAccess.Write, 1);
                var sw = new StreamWriter(fs, new UTF8Encoding(false)) { AutoFlush = true };
                Console.SetOut(sw);
            }
            catch { }
        }

        private static int RunCli(string[] args)
        {
            BindConsole();
            var a0 = args[0].Trim().ToLowerInvariant();
            var rest = args.Skip(1).ToArray();

            if (a0 == "--help" || a0 == "-h" || a0 == "/?") { PrintHelp(); return 0; }
            // 文档同步自检：改完代码跑一下，漏写文档的项会被列出来
            if (a0 == "--doc-check") return DocCheck();

            // 2.1 核心不变量自检（tests.ps1 / build.cmd 门禁调用）
            if (a0 == "--selftest")
            {
                var fails = SteamServerFilterIpBlock.SelfTest.Run(Console.WriteLine);
                return fails == 0 ? 0 : 1;
            }

            // 2.2 状态收敛：从事实源幂等重建全部派生物
            if (a0 == "--reconcile")
            {
                Console.WriteLine("状态收敛（--reconcile）...");
                foreach (var line in SteamServerFilterIpBlock.SelfTest.Reconcile()) Console.WriteLine("  " + line);
                Console.WriteLine("完成。拦截进程会在 5 秒内自动跟随文件变化。");
                return 0;
            }

            if (a0 == "--version" || a0 == "-v")
            {
                Console.WriteLine("FilterTool  构建时间 " + SteamServerFilterIpBlock.BuildStamp.Time);
                try
                {
                    Console.WriteLine("exe 文件时间 " + System.IO.File.GetLastWriteTime(Application.ExecutablePath));
                    Console.WriteLine("exe 大小     " + new System.IO.FileInfo(Application.ExecutablePath).Length + " 字节");
                }
                catch { }
                Console.WriteLine("心跳 build 字段：" + SteamServerFilterIpBlock.IpEngine.HeartbeatFieldOr("build"));
                return 0;
            }

            // 常驻拦截的生命周期（进程 + 计划任务）：唯一实现在 Lifecycle.cs，UI/RulesTool.ps1 都走这里
            if (a0 == "--lifecycle")
            {
                var lifeSub = rest.Length > 0 ? rest[0].Trim().ToLowerInvariant() : "status";
                if (lifeSub == "restart") return SteamServerFilterIpBlock.Lifecycle.CliRestart(Console.WriteLine);
                if (lifeSub == "status") return SteamServerFilterIpBlock.Lifecycle.CliStatus(Console.WriteLine);
                if (lifeSub == "delete-legacy" || lifeSub == "legacy-cleanup")
                    return SteamServerFilterIpBlock.Lifecycle.CliDeleteLegacy(Console.WriteLine);
                Console.WriteLine("用法: FilterTool.exe --lifecycle status|restart|delete-legacy");
                return 2;
            }

            if (a0 == "--layout") return LayoutCheck();

            if (a0 == "--group-list-diagnose")
                return SteamServerFilterIpBlock.GroupListDiagnostics.Run(args.Length >= 2 ? args[1] : null, Console.WriteLine);

            // 组服列表行过滤（原生 DLL 已合并进来；自动注入由 --run 常驻循环负责）
            if (a0 == "--group-filter")
                return SteamServerFilterIpBlock.GroupServerFilter.Run(rest, Console.WriteLine);

            if (a0 == "--shot")
            {
                var path = args.Length >= 2 ? args[1] : Path.Combine(SteamServerFilterRules.Engine.Root, "FilterTool-ui.png");
                Application.EnableVisualStyles();
                Application.SetCompatibleTextRenderingDefault(false);
                using (var f = new UnifiedForm())
                {
                    f.StartPosition = FormStartPosition.Manual;
                    f.Location = new Point(-6000, -6000);
                    f.ShowInTaskbar = false;
                    f.Show();
                    for (int i = 0; i < 24; i++) { Application.DoEvents(); Thread.Sleep(25); }
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

            if (a0 == "--status")
            {
                Console.WriteLine("=== 名字规则层 ===");
                SteamServerFilterRules.Program.Run(new[] { "--status" });
            Console.WriteLine();
                Console.WriteLine("=== IP 拦截层 ===");
                SteamServerFilterIpBlock.Program.Run(new[] { "--status" });
                Console.WriteLine();
                SteamServerFilterIpBlock.GroupServerFilter.Run(new string[0], Console.WriteLine);
                return 0;
            }

            // IP 层
            if (a0 == "--ip" || a0 == "--ip-list") return SteamServerFilterIpBlock.Program.Run(new[] { "--list" });
            if (a0 == "--ip-candidates" || a0 == "--candidates") return SteamServerFilterIpBlock.Program.Run(new[] { "--candidates" });
            if (a0 == "--ip-status") return SteamServerFilterIpBlock.Program.Run(new[] { "--status" });
            if (a0 == "--run" || a0 == "--scan" || a0 == "--resolve" || a0 == "--add-name" ||
                a0 == "--verify" || a0 == "--autostart" || a0 == "--block-family" ||
                a0 == "--add" || a0 == "--remove" || a0 == "--pending" || a0 == "--resolve-pending" ||
                a0 == "--exempt" || a0 == "--unexempt" || a0 == "--bind-name" ||
                a0 == "--logs-prune" || a0 == "--logs-keep" || a0 == "--logs-task" ||
                a0 == "--name-layer" || a0 == "--name-blocked" || a0 == "--mode" || a0 == "--tray" || a0 == "--migrate-engine" || a0 == "--config" || a0 == "--config-audit" || a0 == "--config-migrate")
                return SteamServerFilterIpBlock.Program.Run(args);

            // 列出抓包里的 UDP 通信对端（人正在服里时用它认 IP）
            if (a0 == "--peers")
            {
                if (args.Length < 2) { Console.WriteLine("用法: FilterTool.exe --peers <pcapng> [个数=25]"); return 2; }
                int n = 25;
                if (args.Length > 2 && !int.TryParse(args[2], out n)) { Console.WriteLine("个数必须是整数: " + args[2]); return 2; }   // V-09
                var peers = SteamServerFilterIpBlock.CapLocate.TopPeers(args[1], n);
                Console.WriteLine("UDP 通信对端（包数降序，已排除内网/组播）：");
                foreach (var kv in peers) Console.WriteLine("   " + kv.Key.PadRight(24) + kv.Value + " 包");
                return 0;
            }
            // 只解析一个已有的 pcapng（用于校验解析器，或复用之前抓的包）
            if (a0 == "--parse-capture")
            {
                if (args.Length < 2) { Console.WriteLine("用法: FilterTool.exe --parse-capture <pcapng> [服名片段]"); return 2; }
                var hits = SteamServerFilterIpBlock.CapLocate.ParseFile(args[1], Console.WriteLine);
                Console.WriteLine("共 " + hits.Count + " 个带名字的应答。");
                if (args.Length > 2)
                {
                    var m = SteamServerFilterIpBlock.CapLocate.Match(hits, args[2]);
                    Console.WriteLine("匹配「" + args[2] + "」：" + m.Count + " 个");
                    foreach (var h in m.Take(20)) Console.WriteLine("   " + h.Ip + ":" + h.Port + "   " + h.Name);
                }
                return 0;
            }
            // 抓包定位：抓 N 秒 A2S 报文，找出服名对应的真实 IP（新服唯一可靠的办法）
            if (a0 == "--locate")
            {
                if (args.Length < 2) { Console.WriteLine("用法: FilterTool.exe --locate \"<服名片段>\" [秒数=20]"); return 2; }
                int secs = 20;
                if (args.Length > 2 && !int.TryParse(args[2], out secs)) { Console.WriteLine("秒数必须是整数: " + args[2]); return 2; }   // V-09
                bool force = args.Any(x => string.Equals(x, "--yes", StringComparison.OrdinalIgnoreCase));
                var hits = SteamServerFilterIpBlock.CapLocate.Capture(secs, Console.WriteLine);
                var m = SteamServerFilterIpBlock.CapLocate.Match(hits, args[1]);
                if (m.Count == 0) { Console.WriteLine("× 抓到的 " + hits.Count + " 个应答里没有匹配「" + args[1] + "」的服。"); return 1; }
                Console.WriteLine("匹配到 " + m.Count + " 个：");
                foreach (var h in m.Take(20)) Console.WriteLine("   " + h.Ip + ":" + h.Port + "   " + h.Name);

                // V-28: 关键词兜底可能一次命中一大批服 —— 多 IP 时默认不写，除非显式 --yes
                var ipSet = m.Select(h => h.Ip).Distinct(StringComparer.Ordinal).ToList();
                if (ipSet.Count > 1 && !force)
                {
                    Console.WriteLine("× 匹配到 " + ipSet.Count + " 个不同 IP，为避免误拦默认不写入：");
                    foreach (var ip in ipSet.Take(20)) Console.WriteLine("     " + ip);
                    Console.WriteLine("  确认无误请重跑并加上 --yes：FilterTool.exe --locate \"" + args[1] + "\" " + secs + " --yes");
                    return 3;
                }

                var entries = SteamServerFilterIpBlock.IpEngine.ReadEntries();
                int added = 0;
                foreach (var h in m)
                {
                    var act = SteamServerFilterIpBlock.IpEngine.UpsertEntry(entries, h.Ip, h.Name + "（抓包定位）");   // V-02
                    var linkRule = SteamServerFilterRules.Engine.MatchedRule(h.Name) ?? args[1];
                    SteamServerFilterIpBlock.IpEngine.AddLink(linkRule, h.Ip, h.Name, act == "added", "capture");
                    if (act == "added") added++;
                }
                SteamServerFilterIpBlock.IpEngine.WriteEntries(entries);
                if (added > 0)
                    Console.WriteLine("· 已加入 IP 拦截清单 " + added + " 个：" + string.Join(", ", ipSet.ToArray()));
                else Console.WriteLine("· 这些 IP 都已在拦截清单里（关联已记录）。");
                return 0;
            }
            // 统一动作（与界面里的「添加并拦截」等价）：加名字规则 + 解析 IP + 解析不到就排队等自动补
            if (a0 == "--block")
            {
                if (args.Length < 2) { Console.WriteLine("用法: FilterTool.exe --block \"<服务器名>\" [loose|regex] [restart]"); return 2; }
                return BlockByName(args[1], rest);
            }

            // 名字层
            if (a0 == "--rules" || a0 == "--rules-list") return SteamServerFilterRules.Program.Run(new[] { "--list" });
            if (a0 == "--rules-delete") return SteamServerFilterRules.Program.Run(new[] { "--delete" }.Concat(rest).ToArray());
            if (a0 == "--rules-check") return SteamServerFilterRules.Program.Run(new[] { "--check" }.Concat(rest).ToArray());
            // P2-1：规则校验/添加/生成/备份/恢复统一走 Engine（CLI 与 RulesTool.ps1 共用同一实现）
            if (a0 == "--rules-validate") return SteamServerFilterRules.Program.Run(new[] { "--validate" });
            if (a0 == "--rules-add") return SteamServerFilterRules.Program.Run(new[] { "--add-rule" }.Concat(rest).ToArray());
            if (a0 == "--rules-apply") return SteamServerFilterRules.Program.Run(new[] { "--apply-profile" }.Concat(rest).ToArray());
            if (a0 == "--rules-backup") return SteamServerFilterRules.Program.Run(new[] { "--backup-rules" });
            if (a0 == "--rules-restore") return SteamServerFilterRules.Program.Run(new[] { "--restore-rules" }.Concat(rest).ToArray());
            if (a0 == "--delete")
            {
                var rc = SteamServerFilterRules.Program.Run(args);
                if (rest.Length >= 1 && rc == 0)
                {
                    // 注意：删除是"清理"动作，**不受添加模式影响** —— 无论当前是
                    // 「IP + 名字」还是「只启动名字层」，删规则一律连带释放它带来的 IP，
                    // 否则会留下"规则没了、IP 还在清单里"的孤儿状态（要手工收拾）。
                    List<string> kept, pend;
                    var rel = SteamServerFilterIpBlock.IpEngine.ReleaseIpsForRule(rest[0], out kept, out pend);
                    if (rel.Count > 0)
                        Console.WriteLine("· 已一并释放该名字带来的 IP：" + string.Join(", ", rel.ToArray()));
                    else if (kept.Count > 0)
                        Console.WriteLine("· 关联的 IP 保留（还被别的名字规则引用）：" + string.Join(", ", kept.ToArray()));
                    else
                        Console.WriteLine("· 该名字没有关联的 IP，IP 清单未变动。");
                    foreach (var pn in pend) SteamServerFilterIpBlock.IpEngine.RemovePending(pn);
                    // 无论有没有 IP 关联，都按规则名清一遍 pending —— 否则"加了规则但没解析出 IP"
                    // 的条目会变成孤儿，之后每 5 分钟还徒劳地扫它一次。
                    var pn2 = SteamServerFilterIpBlock.IpEngine.RemovePendingByRule(rest[0]);
                    if (pn2 > 0) Console.WriteLine("· 已清掉 " + pn2 + " 条待解析记录。");
                }
                return rc;
            }
            if (a0 == "--list" || a0 == "--check" || a0 == "--ip-for")
                return SteamServerFilterRules.Program.Run(args);

            if (!a0.StartsWith("-")) return SteamServerFilterRules.Program.Run(args);

            Console.WriteLine("未知参数: " + args[0]);
            PrintHelp();
            return 2;
        }

        /// <summary>命令行版的「添加并拦截」：加名字规则 → 解析 IP → 解析不到就排队等自动补。
        /// 例外：「只启动名字层」模式下跳过整个 IP 解析步骤（与界面行为一致）。</summary>
        private static int BlockByName(string name, string[] options)
        {
            bool loose = true, useRegex = false, restart = false;
            foreach (var o in options)
            {
                var t = o.Trim().ToLowerInvariant();
                if (t == "exact") loose = false;
                else if (t == "loose") loose = true;
                else if (t == "regex") useRegex = true;
                else if (t == "restart") restart = true;
            }

            // 1) 名字层
            var rule = useRegex ? name : SteamServerFilterRules.Engine.NewRuleFromName(name, loose);
            if (useRegex)
            {
                try { new System.Text.RegularExpressions.Regex(name); }
                catch (Exception ex) { Console.WriteLine("非法正则: " + ex.Message); return 2; }
            }
            var already = useRegex ? null : SteamServerFilterRules.Engine.MatchedRule(name);
            var linkRule = already ?? rule;   // 关联用的规则：已有规则覆盖时就用那条
            if (already != null)
            {
                Console.WriteLine("· 名字层已有规则覆盖（命中 " + already + "），跳过加规则。");
            }
            else
            {
                SteamServerFilterRules.Engine.AppendCustom(name, rule);
                if (!string.IsNullOrEmpty(SteamServerFilterRules.Engine.LastGroupFilterNote))
                    Console.WriteLine("· " + SteamServerFilterRules.Engine.LastGroupFilterNote);
                var active = SteamServerFilterRules.Engine.GetActiveProfile();
                if (!SteamServerFilterRules.Engine.ActiveComponents().Contains("custom")) active += "+custom";
                var cnt = SteamServerFilterRules.Engine.ApplyCombo(active);
                Console.WriteLine("· 名字规则已加入：" + rule + "（生效 " + cnt + " 条）");
                if (restart) Console.WriteLine(SteamServerFilterRules.Engine.RestartFilter());
            }

            // 2) IP 层
            // 「只启动名字层」= 添加时也不去找 IP（与界面「添加并拦截」行为一致）：
            // 不解析、不加 IP 清单、不记待解析名单 —— 同 IP 上的其它服完全不受影响。
            if (SteamServerFilterIpBlock.NameLayer.NameOnlyMode)
            {
                Console.WriteLine("· 只启动名字层：已跳过 IP 解析（只按服名拦，不动 IP 清单）。");
                return 0;
            }
            string how;
            List<string> names;
            var ips = SteamServerFilterIpBlock.IpEngine.ResolveIps(name, out how, out names);
            if (ips.Count == 0)
            {
                var queued = SteamServerFilterIpBlock.IpEngine.AddPending(name, linkRule);
                Console.WriteLine("· 暂时解析不出 IP，" + (queued ? "已记入待解析名单" : "已在待解析名单里") + "。");
                Console.WriteLine("  名字规则已生效会先拦住它；之后检测到它的 IP 时会自动补进 IP 拦截清单");
                Console.WriteLine("  （界面每 60 秒查一次；常驻进程 FilterTool.exe --run 也在查）。");
                Console.WriteLine("  也可以现在就把它的 IP 粘进来：FilterTool.exe --add <ip>");
                return 0;
            }
            Console.WriteLine("· 解析依据：" + how + "；匹配 " + names.Count + " 个服名，得到 " + ips.Count + " 个 IP。");
            var added = SteamServerFilterIpBlock.IpEngine.AddNameToBlockList(name, out names, linkRule);
            Console.WriteLine(added.Count > 0
                ? ("· 已加入 IP 拦截清单：" + string.Join(", ", added.ToArray()) +
                   "（关联到规则：" + linkRule + "，删它时会一并释放）")
                : "· 对应 IP 都已在拦截清单里（已记录关联，删规则时会一并释放）。");
            return 0;
        }

        /// <summary>
        /// 文档同步自检：把「帮助里出现的每个参数」「根目录每个状态文件」「_build 每个源码文件」
        /// 拿去 USAGE.md 里找，缺哪个就报哪个。
        /// 项目文档已精简为只保留 README.md：USAGE.md 不存在时直接跳过（构建/CI 门禁仍然通过），
        /// 以后若把 USAGE.md 加回来，这套检查会自动恢复。
        /// </summary>
        private static int DocCheck()
        {
            var rd = SteamServerFilterRules.Engine.Root;
            var readmePath = Path.Combine(rd, "USAGE.md");
            if (!File.Exists(readmePath))
            {
                Console.WriteLine("文档已删除（项目文档只保留 README.md）：跳过文档同步自检 ✓");
                return 0;
            }
            var readme = File.ReadAllText(readmePath, Encoding.UTF8);

            // 1) 命令行参数
            var flags = System.Text.RegularExpressions.Regex.Matches(HelpText(), @"--[a-z][a-z0-9-]*")
                .Cast<System.Text.RegularExpressions.Match>().Select(m => m.Value)
                .Distinct().OrderBy(x => x, StringComparer.Ordinal).ToList();
            var missFlags = flags.Where(x => readme.IndexOf(x, StringComparison.Ordinal) < 0).ToList();

            // 2) 根目录状态文件（只查工具自己产生的那些）
            var files = new[]
            {
                "ip_block.txt", "block_rules.txt", "config.ini", "name_layer.txt", "block_mode.txt", "tray.txt",
                "log_retention.txt", "logs_prune.log", "ip_block.heartbeat.txt",
                "name_ip_map.tsv", "name_ip_links.tsv", "pending_resolve.tsv",
                "name_layer_blocked.txt", "name_layer_seen.tsv",
                "rules-profiles\\custom.txt"
            };
            var missFiles = files.Where(x => readme.IndexOf(x, StringComparison.Ordinal) < 0).ToList();

            // 3) _build 源码文件
            var bdir = Path.Combine(rd, "_build");
            var srcs = Directory.Exists(bdir)
                ? Directory.GetFiles(bdir, "*.cs").Select(Path.GetFileName).OrderBy(x => x, StringComparer.Ordinal).ToList()
                : new List<string>();
            var missSrc = srcs.Where(x => readme.IndexOf(x, StringComparison.Ordinal) < 0).ToList();

            Console.WriteLine("文档同步自检（" + readmePath + "）");
            Console.WriteLine("  命令行参数 " + flags.Count + " 个，未写进文档 " + missFlags.Count + " 个");
            foreach (var x in missFlags) Console.WriteLine("    缺: " + x);
            Console.WriteLine("  状态文件 " + files.Length + " 个，未写进文档 " + missFiles.Count + " 个");
            foreach (var x in missFiles) Console.WriteLine("    缺: " + x);
            Console.WriteLine("  源码文件 " + srcs.Count + " 个，未写进文档 " + missSrc.Count + " 个");
            foreach (var x in missSrc) Console.WriteLine("    缺: " + x);

            // 4.1：头部编译注释里的源文件清单必须等于 _build/*.cs 实际清单
            //      （历史上这里写过"4 个源文件"而实际 9 个，靠人记必出错）
            var missHeader = new List<string>();
            try
            {
                var selfSrc = Path.Combine(bdir, "FilterTool.cs");   // 头部注释就在这个文件里
                if (File.Exists(selfSrc))
                {
                    var head = File.ReadAllText(selfSrc, Encoding.UTF8);
                    foreach (var f in srcs)
                        if (head.IndexOf(f, StringComparison.Ordinal) < 0) missHeader.Add(f);
                }
            }
            catch { }
            Console.WriteLine("  头部编译注释缺失的源文件 " + missHeader.Count + " 个");
            foreach (var x in missHeader) Console.WriteLine("    缺: " + x);

            var n = missFlags.Count + missFiles.Count + missSrc.Count + missHeader.Count;
            Console.WriteLine(n == 0 ? "文档已同步 ✓" : ("★ 有 " + n + " 项没写进文档，请补 USAGE.md"));   // USAGE.md 存在时才可能走到这里
            return n == 0 ? 0 : 1;
        }

        private static IEnumerable<Control> Descendants(Control root)
        {
            foreach (Control c in root.Controls)
            {
                yield return c;
                foreach (var g in Descendants(c)) yield return g;
            }
        }

        private static int LayoutCheck()
        {
            var sizes = new[] { new Size(1120, 900), new Size(1600, 1100), new Size(800, 620), new Size(760, 500), new Size(1000, 700) };
            int issues = 0;
            // 故意不用 using：自检进程在打印结果后直接 Environment.Exit。
            // 原因：窗口销毁阶段会被第三方输入法/钩子挂载拖住，曾出现 --layout 打印完最后一行后
            // 进程不再退出（build 门禁与 CI 一起卡住）。自检是独立进程，跳过清理不影响任何状态。
            var f = new UnifiedForm();
            f.StartPosition = FormStartPosition.Manual;
            f.ShowInTaskbar = false;
            f.Show();
            f.Location = new Point(-6000, -6000);
            foreach (float fontSize in new[] { 9f, 11.25f, 13.5f })
            {
                using (var font = new Font(f.Font.FontFamily, fontSize))
                {
                    f.Font = font;
                    foreach (var size in sizes)
                    {
                        f.ClientSize = size;
                        f.PerformLayout();
                        Console.WriteLine("布局尺寸: " + f.ClientSize.Width + " x " + f.ClientSize.Height + " 字体: " + fontSize);
                        issues += f.CheckResponsiveLayout(Console.WriteLine);
                        foreach (var c in Descendants(f))
                        {
                            if (!c.Visible || !c.Parent.Visible) continue;
                            var parent = c.Parent;
                            if (parent == null) continue;
                            // 滚动内容允许超过视口高度；宽度由 CheckResponsiveLayout 单独检查。
                            if (parent is Panel && ((Panel)parent).AutoScroll && c is Panel) continue;
                            var pr = parent.ClientRectangle;
                            if (c.Left < 0 || c.Top < 0 || c.Right > pr.Width || c.Bottom > pr.Height)
                            {
                                issues++;
                                Console.WriteLine("  越界: {0} \"{1}\" {2} 父客户区={3}", c.GetType().Name, c.Text, c.Bounds, pr);
                            }
                            foreach (Control other in parent.Controls)
                                if (other.TabIndex > c.TabIndex && c.Bounds.IntersectsWith(other.Bounds))
                                {
                                    issues++;
                                    Console.WriteLine("  重叠: {0} / {1}", c.Text, other.Text);
                                }
                        }
                    }
                }
            }
            Console.WriteLine(issues == 0 ? "布局自检通过：15 组尺寸/字体组合，内容适配窗口且无整页横向滚动。" : ("布局自检失败：" + issues + " 处问题。"));
            Console.Out.Flush();
            HardExit(issues == 0 ? 0 : 1);
            return issues == 0 ? 0 : 1;
        }

        private static void PrintHelp() { Console.WriteLine(HelpText()); }

        /// <summary>帮助文本（--help 与 --doc-check 共用同一份，避免两处漂移）。</summary>
        public static string HelpText()
        {
            var sb = new StringBuilder();
            sb.AppendLine("SteamServerFilter 拦截工具（单一界面：输入服务器名 → 名字和 IP 一起拦）");
            sb.AppendLine("  FilterTool.exe                        打开界面");
            sb.AppendLine();
            sb.AppendLine("名字规则层：");
            sb.AppendLine("  FilterTool.exe \"<服务器名>\" [loose|regex] [restart]");
            sb.AppendLine("  FilterTool.exe --list / --delete \"<规则>\" / --check \"<服务器名>\"");
            sb.AppendLine("  FilterTool.exe --ip-for \"<服务器名>\"    按名字解析出 IP 并加入 IP 清单");
            sb.AppendLine("  FilterTool.exe --rules-validate        校验 block_rules.txt（编码/BOM/重复/乱码/非法正则/与统一规则文件同步）");
            sb.AppendLine("  FilterTool.exe --rules-add \"<服务器名>\" [exact|loose|regex] [restart]  加进 custom 档并重建（CLI/PS 共用）");
            sb.AppendLine("  FilterTool.exe --rules-apply [custom] [restart]  按统一规则文件重建 block_rules.txt（先备份）");
            sb.AppendLine("  FilterTool.exe --rules-backup          备份当前 block_rules.txt");
            sb.AppendLine("  FilterTool.exe --rules-restore <备份> [restart]  从备份恢复 block_rules.txt（先备份当前）");
            sb.AppendLine();
            sb.AppendLine("IP 拦截层：");
            sb.AppendLine("  FilterTool.exe --ip                    列出 IP 拦截清单");
            sb.AppendLine("  FilterTool.exe --candidates            候选 IP（含安全性判定）");
            sb.AppendLine("  FilterTool.exe --block-family          拦下所有『服名全命中现规则』的 IP");
            sb.AppendLine("  FilterTool.exe --add <ip|cidr|ip:udp-port> [备注] / --remove <ip|cidr|ip:udp-port>");
            sb.AppendLine("  FilterTool.exe --add-name \"<服务器名>\"  / --resolve \"<服务器名>\"");
            sb.AppendLine("  FilterTool.exe --scan [超时ms]          重建 名字↔IP 表");
            sb.AppendLine("  FilterTool.exe --locate \"<服名>\" [秒]    抓包定位（这 N 秒内刷新一次浏览器）");
            sb.AppendLine("  FilterTool.exe --peers <pcapng>         列出抓包里的 UDP 对端（人在服里时认 IP）");
            sb.AppendLine("  FilterTool.exe --logs-prune [天数]      立即清理旧日志（默认保留 30 天）");
            sb.AppendLine("  FilterTool.exe --logs-keep <天数>       设置日志保留天数");
            sb.AppendLine("  FilterTool.exe --logs-task on|off       每 3 天自动清理日志的计划任务");
            sb.AppendLine("  FilterTool.exe --tray on|off            常驻进程是否显示右下角托盘图标（默认显示）");
            sb.AppendLine("  FilterTool.exe --name-layer on|off      内置名字层：自己按服务器名丢包（替代 SteamServerFilter）");
            sb.AppendLine("  FilterTool.exe --name-blocked           列出被名字层封掉的端点");
            sb.AppendLine("  FilterTool.exe --pending                列出待解析服名（等自动补 IP）");
            sb.AppendLine("  FilterTool.exe --resolve-pending        立即尝试解析待解析服名");
            sb.AppendLine("  FilterTool.exe --block \"<服务器名>\" [loose|regex|restart]   界面「添加并拦截」的命令行版");
            sb.AppendLine("  FilterTool.exe --run [秒数]             常驻 IP 拦截（开机自启用）");
            sb.AppendLine("  FilterTool.exe --verify <ip:port> / --autostart on|off");
            sb.AppendLine();
            sb.AppendLine("  FilterTool.exe --selftest               核心不变量自检（返回码 1 = 有失败）");
            sb.AppendLine("  FilterTool.exe --reconcile              状态收敛：从事实源重建全部派生物");
            sb.AppendLine("  FilterTool.exe --config [key value|audit|migrate]  统一开关 config.ini（name-layer/mode/tray/log-keep/active-profile）");
            sb.AppendLine("  FilterTool.exe --config-audit            审计 config.ini 与旧单值文件的取值/冲突（token 不含明文）");
            sb.AppendLine("  FilterTool.exe --config-migrate          把旧开关（含 .active-profile）迁入 config.ini（旧文件保留）");
            sb.AppendLine("  FilterTool.exe --migrate-engine         迁移到内置名字层并停用旧 SteamServerFilter（含回滚说明）");
            sb.AppendLine("  FilterTool.exe --lifecycle [status|restart|delete-legacy]  常驻拦截进程/计划任务：查看、重启、删除旧入口任务");
            sb.AppendLine("  FilterTool.exe --version                构建时间与 exe 信息");
            sb.AppendLine("  FilterTool.exe --group-list-diagnose [L4D2目录]  只读诊断组服/匹配通路线索（不隐藏列表行）");
            sb.AppendLine();
            sb.AppendLine("组服列表过滤层（Steam 组战役模式服务器列表里按服名删行；原生 DLL 已内嵌）：");
            sb.AppendLine("  FilterTool.exe --group-filter                 状态（进程/指纹/Hook/规则/日志路径）");
            sb.AppendLine("  FilterTool.exe --group-filter init            解包内嵌 DLL 并生成 ini（不注入）");
            sb.AppendLine("  FilterTool.exe --group-filter verify          只读门禁：进程 + gameui 指纹 + 远端模块/字节/虚表");
            sb.AppendLine("  FilterTool.exe --group-filter inject          立即注入（游戏已启动且已加载 gameui.dll）");
            sb.AppendLine("  FilterTool.exe --group-filter stop            停止过滤并恢复原始 9 字节（DLL 驻留不卸载）");
            sb.AppendLine("  FilterTool.exe --group-filter reload          按规则文件重建 ini，并让已注入的进程重读");
            sb.AppendLine("  FilterTool.exe --group-filter rules           显示规则文件、路径和生成的正则");
            sb.AppendLine("  FilterTool.exe --group-filter passthrough on|off  临时放行匹配行（前后对比用）");
            sb.AppendLine("  FilterTool.exe --group-filter auto on|off     独立层总开关（默认 on=常开）；off 仅供排障，--run 不会自动拉起");
            sb.AppendLine("  FilterTool.exe --group-filter resident        独立监视进程（内部用：游戏启动后自动注入，界面/--run 拉起）");
            sb.AppendLine("  FilterTool.exe --group-filter mode filter|diag  filter=真正删行；diag=只记录不删行");
            sb.AppendLine("  FilterTool.exe --group-filter dedupe on|off    重复名称过滤：每一遍重建中，同名或仅末尾 #编号不同只保留第一条（默认 on）");
            sb.AppendLine("  FilterTool.exe --group-filter watch [秒数]    只跑自动注入监视循环（不开 WinDivert，用于验证）");
            sb.AppendLine("  统一规则文件：rules-profiles\\custom.txt（UTF-8，一行一条；名字层丢包与组服列表删行共用）");
            sb.AppendLine();
            sb.AppendLine("通用：--status · --layout · --shot <png> · --doc-check");
            return sb.ToString();
        }
    }
}
