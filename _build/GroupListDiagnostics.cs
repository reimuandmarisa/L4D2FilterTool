using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;
using Microsoft.Win32;

namespace SteamServerFilterIpBlock
{
    internal static class GroupListDiagnostics
    {
        internal static readonly string[] ClientMarkers =
        {
            "GroupServer", "SteamMatchGameSearch001", "JoinSteamGroup", "m_iServerSteamGroupID"
        };

        internal static readonly string[] BrowserMarkers =
        {
            "SteamMatchMakingServers002", "CServerBrowserDialog", "ServerBrowser.vdf"
        };

        internal static List<string> DetectMarkers(string text, IEnumerable<string> markers)
        {
            var found = new List<string>();
            if (string.IsNullOrEmpty(text) || markers == null) return found;
            foreach (var marker in markers)
                if (!string.IsNullOrEmpty(marker) && text.IndexOf(marker, StringComparison.Ordinal) >= 0)
                    found.Add(marker);
            return found;
        }

        private static string ReadAscii(string path)
        {
            if (string.IsNullOrEmpty(path) || !File.Exists(path)) return "";
            using (var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite))
            using (var reader = new StreamReader(stream, Encoding.ASCII, false)) return reader.ReadToEnd();
        }

        private static string SteamRootFromRegistry()
        {
            foreach (var view in new[] { RegistryView.Registry64, RegistryView.Registry32 })
            {
                try
                {
                    using (var baseKey = RegistryKey.OpenBaseKey(RegistryHive.CurrentUser, view))
                    using (var key = baseKey.OpenSubKey(@"Software\Valve\Steam"))
                    {
                        if (key == null) continue;
                        foreach (var name in new[] { "SteamPath", "InstallPath" })
                        {
                            var value = key.GetValue(name) as string;
                            if (!string.IsNullOrWhiteSpace(value) && Directory.Exists(value)) return value;
                        }
                    }
                }
                catch { }
            }
            return null;
        }

        private static IEnumerable<string> SteamRoots()
        {
            var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            var registered = SteamRootFromRegistry();
            if (!string.IsNullOrEmpty(registered) && seen.Add(registered)) yield return registered;
            foreach (var candidate in new[]
            {
                Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86) + @"\Steam",
                Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles) + @"\Steam",
                @"C:\Steam", @"D:\Steam"
            })
            {
                if (Directory.Exists(candidate) && seen.Add(candidate)) yield return candidate;
            }
        }

        private static List<string> LibraryRoots(string steamRoot)
        {
            var roots = new List<string> { steamRoot };
            var vdf = Path.Combine(steamRoot, "steamapps", "libraryfolders.vdf");
            if (!File.Exists(vdf)) vdf = Path.Combine(steamRoot, "config", "libraryfolders.vdf");
            try
            {
                if (File.Exists(vdf))
                {
                    var text = File.ReadAllText(vdf, Encoding.UTF8);
                    foreach (Match m in Regex.Matches(text, "\\\"path\\\"\\s*\\\"((?:\\\\\\\"|[^\\\"])*)\\\"", RegexOptions.IgnoreCase))
                    {
                        var path = m.Groups[1].Value.Replace("\\\\", "\\").Replace("\\\"", "\"");
                        if (Directory.Exists(path) && !roots.Contains(path, StringComparer.OrdinalIgnoreCase)) roots.Add(path);
                    }
                }
            }
            catch { }
            return roots;
        }

        internal static string FindInstallPath(string requested)
        {
            if (!string.IsNullOrWhiteSpace(requested))
            {
                var full = Path.GetFullPath(requested.Trim().Trim('"'));
                if (File.Exists(Path.Combine(full, "left4dead2", "bin", "client.dll"))) return full;
                if (File.Exists(Path.Combine(full, "bin", "client.dll"))) return full;
                return full;
            }

            foreach (var steamRoot in SteamRoots())
            foreach (var library in LibraryRoots(steamRoot))
            {
                var install = Path.Combine(library, "steamapps", "common", "Left 4 Dead 2");
                if (File.Exists(Path.Combine(install, "left4dead2", "bin", "client.dll"))) return install;
            }
            return null;
        }

        public static int Run(string requestedPath, Action<string> write)
        {
            if (write == null) write = Console.WriteLine;
            var install = FindInstallPath(requestedPath);
            write("L4D2 Steam 组服列表诊断（只读；不改 Steam、规则、拦截清单或网络设置）");
            if (string.IsNullOrEmpty(install) || !Directory.Exists(install))
            {
                write("未找到 L4D2 安装目录。可传入完整路径：FilterTool.exe --group-list-diagnose \"D:\\steam\\steamapps\\common\\Left 4 Dead 2\"");
                return 0;
            }

            write("游戏目录：" + install);
            var gameDir = Path.Combine(install, "left4dead2");
            var clientPath = Path.Combine(gameDir, "bin", "client.dll");
            var client = ReadAscii(clientPath);
            var clientMarkers = DetectMarkers(client, ClientMarkers);
            write("client.dll 组服/匹配标记：" + (clientMarkers.Count > 0 ? string.Join(", ", clientMarkers.ToArray()) : "未找到"));

            var browserPath = Path.Combine(install, "bin", "serverbrowser.dll");
            var browser = ReadAscii(browserPath);
            var browserMarkers = DetectMarkers(browser, BrowserMarkers);
            write("serverbrowser.dll 通用浏览器标记：" + (browserMarkers.Count > 0 ? string.Join(", ", browserMarkers.ToArray()) : "未找到"));

            var englishPath = Path.Combine(install, "update", "resource", "l4d360ui_tu_english.txt");
            var english = File.Exists(englishPath) ? ReadAscii(englishPath) : "";
            var groupUi = DetectMarkers(english, new[]
            {
                "L4D360UI_FoundGroupGames_Title_addon", "L4D360UI_ServerType_Group", "L4D360UI_MainMenu_PlayOnGroupServer"
            });
            write("组服 UI 本地化标记：" + (groupUi.Count > 0 ? string.Join(", ", groupUi.ToArray()) : "未找到或资源不在 loose 文件中"));

            write("判断：当前 FilterTool 只处理 WinDivert 可见的 IP/UDP/A2S 流量；没有读取或改写 L4D2 的组服候选列表，也没有按列表显示名隐藏单行的接口。");
            write("这些二进制字符串表明存在独立的组服/游戏搜索客户端路径，但不能据此确定具体 Steam CM service、URI、缓存位置或条目超时策略。");
            write("因此，阻断已确认 endpoint 可以阻止该 endpoint 的网络流量，却不保证 PLUS 行从组服列表消失；不要用通用 Steam API/CM 域名屏蔽来代替行过滤。");
            write("验证建议：分别记录刷新前后的列表行、同一时段 A2S 抓包结果与 endpoint 阻断状态。此诊断命令本身不改变任何状态，无需回滚。");
            return 0;
        }
    }
}
