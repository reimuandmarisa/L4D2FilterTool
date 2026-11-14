// ============================================================================
//  SteamServerFilter 规则添加器  (RulesAdd)
//  可以直接输入服务器名加规则，并浏览/删除全部生效规则。
//
//  它复刻了 SteamServerFilter 规则引擎的确切行为（已逆向确认）：
//    * block_rules.txt 必须 UTF-8（无 BOM）
//    * 每行一条 .NET 正则，# 开头的注释行、空行在生成时被剥离
//    * 完全相同的行会被引擎去重
//    * 对服务器名做 Regex.IsMatch（区分大小写、不锚定）
//
//  编译： Roslyn csc.exe /target:winexe /win32manifest:RulesAdd.manifest
//  用法： 双击打开界面；或命令行见 --help
// ============================================================================

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Drawing;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Windows.Forms;

namespace SteamServerFilterRules
{
    // ------------------------------------------------------------- 规则条目
    internal sealed class RuleEntry
    {
        public string Rule = "";
        public string Source = "";   // rpg.txt / custom.txt ...
        public string Note = "";     // 规则上方那行注释
        public int Hits = -1;        // -1 = 未统计

        public ListViewItem ToItem()
        {
            var it = new ListViewItem(Rule);
            it.SubItems.Add(Source);
            it.SubItems.Add(Hits < 0 ? "-" : Hits.ToString());
            it.SubItems.Add(Note);
            it.Tag = this;
            return it;
        }
    }

    // ------------------------------------------------------------------ 引擎
    internal static class Engine
    {
        public static string Root = AppDomain.CurrentDomain.BaseDirectory;

        public static readonly Encoding Utf8NoBom = new UTF8Encoding(false);
        private static readonly Encoding Utf8Strict = new UTF8Encoding(false, true);

        // 生命周期统一在 SteamServerFilterIpBlock.Lifecycle 实现（进程/计划任务/重启），这里只做别名。
        // 旧引擎 SteamServerFilter.exe 已归档到 _archive\legacy-binaries。
        public const string TaskName = SteamServerFilterIpBlock.Lifecycle.TaskName;
        public const string FilterExeName = SteamServerFilterIpBlock.Lifecycle.ExeName;

        public static string RulesFile  { get { return Path.Combine(Root, "block_rules.txt"); } }
        public static string ProfileDir { get { return Path.Combine(Root, "rules-profiles"); } }
        public static string CustomFile { get { return Path.Combine(ProfileDir, "custom.txt"); } }
        public static string StateFile  { get { return Path.Combine(ProfileDir, ".active-profile"); } }
        public static string BackupDir  { get { return Path.Combine(ProfileDir, ".backup"); } }
        public static string LogDir     { get { return Path.Combine(Root, "Logs"); } }

        private static readonly TimeSpan RxTimeout = TimeSpan.FromSeconds(2);

        // ---- 文件读写（程序运行时会占用当天日志，必须共享读） ----
        public static string ReadTextShared(string path)
        {
            using (var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite))
            using (var sr = new StreamReader(fs, Encoding.UTF8, true))
                return sr.ReadToEnd();
        }

        private static string[] SplitLines(string text)
        {
            return text.Replace("\r\n", "\n").Replace('\r', '\n').Split('\n');
        }

        public static List<string> OrdinalDistinct(IEnumerable<string> items)
        {
            var seen = new HashSet<string>(StringComparer.Ordinal);
            var outp = new List<string>();
            foreach (var i in items) if (seen.Add(i)) outp.Add(i);
            return outp;
        }

        // ---- 规则档 ----
        public static List<string> ReadProfileRules(string combo)
        {
            var outp = new List<string>();
            foreach (var raw in combo.Split('+'))
            {
                var name = raw.Trim();
                if (name.Length == 0) continue;
                var f = Path.Combine(ProfileDir, name + ".txt");
                if (!File.Exists(f)) throw new FileNotFoundException("找不到规则文件: " + f);
                foreach (var line in SplitLines(ReadTextShared(f)))
                {
                    if (string.IsNullOrWhiteSpace(line)) continue;
                    if (line.TrimStart().StartsWith("#")) continue;
                    outp.Add(line.Trim());
                }
            }
            return OrdinalDistinct(outp);
        }

        /// <summary>当前档位的全部规则，带上来源文件与上方注释，供界面浏览。</summary>
        public static List<RuleEntry> ReadActiveRulesDetailed()
        {
            var seen = new HashSet<string>(StringComparer.Ordinal);
            var list = new List<RuleEntry>();
            foreach (var comp in ActiveComponents())
            {
                var f = Path.Combine(ProfileDir, comp + ".txt");
                if (!File.Exists(f)) continue;
                var note = "";
                foreach (var line in SplitLines(ReadTextShared(f)))
                {
                    if (string.IsNullOrWhiteSpace(line)) { continue; }
                    var t = line.Trim();
                    if (t.StartsWith("#")) { note = t.TrimStart('#').Trim(); continue; }
                    if (seen.Add(t))
                        list.Add(new RuleEntry { Rule = t, Source = comp + ".txt", Note = note });
                    note = "";
                }
            }
            return list;
        }

        public static string[] ActiveComponents()
        {
            return GetActiveProfile().Split('+').Select(x => x.Trim()).Where(x => x.Length > 0).ToArray();
        }

        public static List<string> AvailableProfiles()
        {
            var outp = new List<string>();
            if (!Directory.Exists(ProfileDir)) return outp;
            foreach (var f in Directory.GetFiles(ProfileDir, "*.txt"))
                outp.Add(Path.GetFileNameWithoutExtension(f));
            outp.Sort(StringComparer.OrdinalIgnoreCase);
            return outp;
        }

        // ---- 引擎视角：block_rules.txt 里真正生效的规则 ----
        public static List<string> ReadEngineRules()
        {
            if (!File.Exists(RulesFile)) return new List<string>();
            var text = Encoding.UTF8.GetString(File.ReadAllBytes(RulesFile)); // 非法字节 -> U+FFFD
            if (text.Length > 0 && text[0] == '\uFEFF') text = text.Substring(1);
            return OrdinalDistinct(SplitLines(text).Where(l => !string.IsNullOrWhiteSpace(l)));
        }

        public static bool RulesFileIsValidUtf8()
        {
            if (!File.Exists(RulesFile)) return true;
            try { Utf8Strict.GetString(File.ReadAllBytes(RulesFile)); return true; }
            catch { return false; }
        }

        public static bool RuleIsMangled(string rule)
        {
            return rule.IndexOf('\uFFFD') >= 0;
        }

        /// <summary>block_rules.txt 是否与当前档位一致（不一致说明改完还没重新生成）。</summary>
        public static bool IsRulesFileInSync()
        {
            try
            {
                var want = ReadProfileRules(GetActiveProfile());
                var have = ReadEngineRules();
                return want.SequenceEqual(have, StringComparer.Ordinal);
            }
            catch { return false; }
        }

        // ---- 当前规则文件（P2-2：config.ini 为主事实源，.active-profile 只作兼容回退） ----
        // 规则统一后只有一个 rules-profiles\custom.txt；旧的多档位组合（rpg+custom+pureplus）
        // 在首次启动时会被归档，这里发现旧组合里的文件已不存在就自动回退到 custom。
        public static string GetActiveProfile()
        {
            // 规则统一后只有一个 rules-profiles\custom.txt：标记存在时忽略遗留的档位组合
            //（旧 config 里可能还是 rpg+custom+pureplus，但对应文件已被归档）。
            try { if (File.Exists(UnifiedMarker)) return "custom"; } catch { }
            try
            {
                var cv = SteamServerFilterIpBlock.Config.Get("active-profile");
                if (cv != null && cv.Trim().Length > 0) return cv.Trim();
            }
            catch { }
            try
            {
                if (File.Exists(StateFile))
                {
                    var sv = File.ReadAllText(StateFile, Utf8NoBom).Trim();
                    if (sv.Length > 0) return sv;
                }
            }
            catch { }
            return "custom";
        }

        public static void SetActiveProfile(string name)
        {
            var v = (name ?? "").Trim();
            if (v.Length == 0) v = "custom";
            Directory.CreateDirectory(ProfileDir);
            // 旧文件继续写：旧版本/手工脚本仍会读它；config.ini 才是新的主事实源。
            SteamServerFilterIpBlock.SafeFile.Write(StateFile, v);
            try { SteamServerFilterIpBlock.Config.Set("active-profile", v); } catch { }
        }

        // ---- 生成 block_rules.txt ----
        public static List<string> WriteRulesFile(IEnumerable<string> rules)
        {
            var cleaned = OrdinalDistinct(rules.Select(r => r.Trim()).Where(r => r.Length > 0));
            SteamServerFilterIpBlock.SafeFile.Write(RulesFile, string.Join("\r\n", cleaned) + "\r\n");
            return cleaned;
        }

        public static int ApplyCombo(string combo)
        {
            // V-11: 生成 block_rules.txt 之前先确认所有用到的规则档都是合法 UTF-8。
            // 否则 GBK 档会被按 UTF-8 读成 U+FFFD，写进 block_rules.txt 就是一批死规则 —— 返回 -1 拒绝生成。
            BrokenProfiles.Clear();
            foreach (var comp in combo.Split('+'))
            {
                var f = Path.Combine(ProfileDir, comp.Trim() + ".txt");
                if (File.Exists(f) && !IsValidUtf8File(f))
                {
                    BrokenProfiles.Add(comp.Trim() + ".txt");
                    Console.WriteLine("× 规则文件 " + comp.Trim() + ".txt 不是合法 UTF-8（可能是记事本存成了 ANSI/GBK）。");
                    Console.WriteLine("  已拒绝生成 block_rules.txt —— 否则中文规则会全部变成乱码死规则。");
                    Console.WriteLine("  请用支持 UTF-8 的编辑器把它另存为「UTF-8 无 BOM」后重试。");
                }
            }
            if (BrokenProfiles.Count > 0) return -1;

            var rules = ReadProfileRules(combo);
            var written = WriteRulesFile(rules);
            SetActiveProfile(combo);
            return written.Count;
        }

        // ---- 统一规则文件：把旧的「多档位规则 + 独立组服过滤规则」合并成一个文件 ----

        /// <summary>V-20：一次性把旧的「多档位规则文件（rpg/custom/pureplus…）+ 独立的组服过滤规则文件
        /// group_filter_rules.txt」合并成一个统一规则文件 rules-profiles\custom.txt。
        /// 合并后名字层丢包与组服列表删行共用同一套规则，界面/CLI 不再区分档位。
        /// 幂等：成功后写 rules-profiles\.unified 标记，之后直接返回。失败不抛异常。</summary>
        public static void EnsureUnifiedRules()
        {
            try
            {
                Directory.CreateDirectory(ProfileDir);
                if (File.Exists(UnifiedMarker)) return;

                var oldGroupFile = Path.Combine(Root, "group_filter_rules.txt");
                var profileFiles = Directory.Exists(ProfileDir)
                    ? Directory.GetFiles(ProfileDir, "*.txt")
                    : new string[0];
                bool legacy = File.Exists(oldGroupFile) ||
                              profileFiles.Any(f => !string.Equals(Path.GetFileName(f), "custom.txt", StringComparison.OrdinalIgnoreCase));
                if (!legacy && File.Exists(CustomFile))
                {
                    // 已经是统一布局（例如标记文件被误删）：只补标记，不动规则
                    WriteUnifiedMarker();
                    return;
                }

                var seen = new HashSet<string>(StringComparer.Ordinal);
                var all = new List<string>();
                Action<IEnumerable<string>> add = src =>
                {
                    foreach (var r in src)
                    {
                        var t = (r ?? "").Trim();
                        if (t.Length == 0) continue;
                        if (t.StartsWith("#") || t.StartsWith(";")) continue;
                        if (seen.Add(t)) all.Add(t);
                    }
                };

                // 1) 当前真正生效的规则（block_rules.txt = 各启用档的并集）
                add(ReadEngineRules());
                // 2) 旧的独立组服过滤规则：去锚点 + 解开 .*(?:X).* 包装
                if (File.Exists(oldGroupFile))
                    add(SplitLines(ReadTextShared(oldGroupFile)).Select(UnwrapGroupFilterRule));
                // 3) 一条规则都没有（全新安装）时，用内置默认规则做种子
                if (all.Count == 0)
                {
                    add(DefaultRpgLines);
                    add(SplitLines(SteamServerFilterIpBlock.GroupServerFilter.DefaultRulesText).Select(UnwrapGroupFilterRule));
                }

                // 4) 备份旧 custom.txt；其余档位文件全部归档（含未启用的档，避免再出现「档位」概念）
                if (File.Exists(CustomFile)) BackupProfileFile(CustomFile);
                var archive = Path.Combine(ProfileDir, "archive");
                int archived = 0;
                foreach (var f in profileFiles)
                {
                    if (string.Equals(Path.GetFileName(f), "custom.txt", StringComparison.OrdinalIgnoreCase)) continue;
                    try
                    {
                        Directory.CreateDirectory(archive);
                        File.Move(f, Path.Combine(archive, Path.GetFileNameWithoutExtension(f) + "." +
                            DateTime.Now.ToString("yyyyMMdd-HHmmss") + ".bak"));
                        archived++;
                    }
                    catch { }
                }
                if (File.Exists(oldGroupFile))
                {
                    try
                    {
                        Directory.CreateDirectory(archive);
                        File.Move(oldGroupFile, Path.Combine(archive, "group_filter_rules." +
                            DateTime.Now.ToString("yyyyMMdd-HHmmss") + ".bak"));
                    }
                    catch { }
                }

                // 5) 写统一规则文件
                var sb = new StringBuilder();
                sb.Append(CustomHeader);
                sb.Append("\r\n# ---------------- 规则（一行一条，删除一行就少一条） ----------------\r\n");
                foreach (var r in all) sb.Append(r).Append("\r\n");
                SteamServerFilterIpBlock.SafeFile.Write(CustomFile, sb.ToString());   // V-05: 原子写

                // 6) 固定只有一个档位 custom，并重建 block_rules.txt
                ApplyCombo("custom");
                WriteUnifiedMarker();
                Console.WriteLine("规则文件已统一：rules-profiles\\custom.txt（共 " + all.Count + " 条；归档旧档位文件 " + archived + " 个）。");
            }
            catch (Exception ex)
            {
                // 迁移失败不阻断启动：保留旧文件不动，下次启动会再试
                Console.WriteLine("提示: 统一规则文件迁移未完成（" + ex.Message + "），本次继续按旧规则运行。");
            }
        }

        private static void WriteUnifiedMarker()
        {
            try
            {
                SteamServerFilterIpBlock.SafeFile.Write(UnifiedMarker,
                    "unified " + DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss") + "\r\n" +
                    "rules=" + ReadCustomRules().Count + "\r\n");
            }
            catch { }
        }

        /// <summary>把旧组服过滤规则行还原成一条裸规则：去掉 ^…$ 锚点，解开 .*(?:X).* 包装。</summary>
        private static string UnwrapGroupFilterRule(string line)
        {
            var t = (line ?? "").Trim();
            if (t.Length == 0) return t;
            if (t.StartsWith("^")) t = t.Substring(1);
            if (t.EndsWith("$")) t = t.Substring(0, t.Length - 1);
            t = t.Trim();
            if (t.Length > 8 && t.StartsWith(".*(?:", StringComparison.Ordinal) && t.EndsWith(").*", StringComparison.Ordinal))
                t = t.Substring(5, t.Length - 8);
            return t.Trim();
        }

        // ---- 规则生成 ----
        public static string NewRuleFromName(string name, bool loose)
        {
            var exact = Regex.Escape(name.Trim());
            return loose ? Regex.Replace(exact, @"\d+", @"\d+") : exact;
        }

        public static string MatchedRule(string name)
        {
            foreach (var r in ReadEngineRules())
            {
                try
                {
                    if (Regex.IsMatch(name, r, RegexOptions.None, RxTimeout)) return r;
                }
                catch { }
            }
            return null;
        }

        // ---- 统一规则文件（名字层 + 组服列表过滤共用同一套规则） ----
        private const string CustomHeader =
            "# ============================================================\r\n" +
            "# 统一拦截规则文件（UTF-8，一行一条；支持 # 注释）\r\n" +
            "# ============================================================\r\n" +
            "# 这里是【唯一】的规则来源，两层共用同一套规则：\r\n" +
            "#   * 名字层：按 A2S 服名丢包（服务器名任意位置命中即拦截）\r\n" +
            "#   * 组服列表过滤：从「Steam 组战役模式服务器」列表里删行（对显示名整串匹配）\r\n" +
            "# 界面上「添加并拦截」会自动往这里追加；也可以直接编辑本文件，保存后约 1 秒内两层自动生效。\r\n" +
            "# 不区分「默认档 / 自定义档」：所有规则都在这一个文件里，删掉一行就少一条规则。\r\n" +
            "# ============================================================\r\n";

        /// <summary>统一规则文件的迁移标记（存在 = 已合并，不再重复迁移）。</summary>
        public static string UnifiedMarker { get { return Path.Combine(ProfileDir, ".unified"); } }

        // ---- 统一规则文件里的「范围」标记 ----
        // 一条规则默认同时用于：名字层（按 A2S 服名丢包）+ 组服列表过滤（从 Steam 组战役模式服务器列表删行）。
        // 添加时取消「同时加入组服列表过滤名称」的规则会被下面这对标记包起来：名字层照常用，组服列表不删这一行。
        public const string NameOnlyStart = "# >>> 仅名字层（不删组服列表行）";
        public const string NameOnlyEnd   = "# <<< 仅名字层";

        /// <summary>统一规则文件里的一条规则，以及它是否参与组服列表过滤。</summary>
        public sealed class UnifiedRule
        {
            public string Rule;
            public bool GroupFilter;
        }

        /// <summary>按行读统一规则文件，并识别「仅名字层」标记段。
        /// 不能用 ReadProfileRules：它会丢掉注释行，看不到标记。</summary>
        public static List<UnifiedRule> ReadUnifiedRules()
        {
            var outp = new List<UnifiedRule>();
            if (!File.Exists(CustomFile)) return outp;
            var seen = new HashSet<string>(StringComparer.Ordinal);
            bool nameOnly = false;
            foreach (var line in SplitLines(ReadTextShared(CustomFile)))
            {
                if (string.IsNullOrWhiteSpace(line)) continue;
                var t = line.Trim();
                if (t.StartsWith("#"))
                {
                    if (t.StartsWith(NameOnlyStart, StringComparison.Ordinal)) nameOnly = true;
                    else if (t.StartsWith(NameOnlyEnd, StringComparison.Ordinal)) nameOnly = false;
                    continue;
                }
                if (!seen.Add(t)) continue;
                outp.Add(new UnifiedRule { Rule = t, GroupFilter = !nameOnly });
            }
            return outp;
        }

        public static void EnsureCustomFile()
        {
            Directory.CreateDirectory(ProfileDir);
            if (!File.Exists(CustomFile)) SteamServerFilterIpBlock.SafeFile.Write(CustomFile, CustomHeader);
        }

        public static List<string> ReadCustomRules()
        {
            if (!File.Exists(CustomFile)) return new List<string>();
            return ReadProfileRules("custom");
        }

        /// <summary>上一次 AppendCustom 时组服列表过滤层的同步结果（给界面/CLI 打日志用；没同步时为 null）。</summary>
        public static string LastGroupFilterNote { get; private set; }

        /// <summary>把一条规则追加进统一规则文件 custom.txt；返回 false 表示已存在。
        /// 默认同时用于名字层丢包 + 组服列表删行（两层共用同一条规则，不再有第二个规则文件）。</summary>
        public static bool AppendCustom(string serverName, string rule)
        {
            return AppendCustom(serverName, rule, true);
        }

        /// <summary>追加一条规则。alsoGroupFilter=true：名字层丢包 + Steam 组服列表删行都生效；
        /// false：只用于名字层丢包，规则会被「仅名字层」标记段包住，组服列表保留这一行。</summary>
        public static bool AppendCustom(string serverName, string rule, bool alsoGroupFilter)
        {
            EnsureCustomFile();
            // V-10: 服名来自 A2S（外部输入），含 \r\n 会把一条规则拆成多行、
            // 多出来的行会变成一条不可控的正则；规则本身也必须单行。
            serverName = SteamServerFilterIpBlock.SafeFile.CleanName(serverName);
            rule = SteamServerFilterIpBlock.SafeFile.Clean(rule);
            LastGroupFilterNote = null;
            if (rule.Length == 0) return false;

            UnifiedRule existing = null;
            foreach (var x in ReadUnifiedRules())
                if (string.Equals(x.Rule, rule, StringComparison.Ordinal)) { existing = x; break; }

            if (existing != null && existing.GroupFilter == alsoGroupFilter)
            {
                LastGroupFilterNote = alsoGroupFilter
                    ? "统一规则文件里已有这条规则（名字层与组服列表过滤共用，不会重复添加）。"
                    : "统一规则文件里已有这条规则（已经用于名字层，不会重复添加）。";
                return false;
            }

            bool changedScope = existing != null;
            if (changedScope) RemoveRuleLine(rule);   // 范围变了：先删旧行，再按新范围追加

            var stamp = "(" + DateTime.Now.ToString("yyyy-MM-dd HH:mm") + ")";
            var block = alsoGroupFilter
                ? "\r\n# " + serverName + "  " + stamp + "\r\n" + rule + "\r\n"
                : "\r\n" + NameOnlyStart + "\r\n# " + serverName + "  " + stamp + "\r\n" + rule + "\r\n" + NameOnlyEnd + "\r\n";
            var oldTxt = File.Exists(CustomFile) ? ReadTextShared(CustomFile) : CustomHeader;
            SteamServerFilterIpBlock.SafeFile.Write(CustomFile, oldTxt + block);   // V-05: 原子写

            if (changedScope)
                LastGroupFilterNote = alsoGroupFilter
                    ? "已更新这条规则的范围：名字层丢包 + Steam 组服列表删行都生效。"
                    : "已更新这条规则的范围：只用于名字层丢包（组服列表不删这一行）。";
            else
                LastGroupFilterNote = alsoGroupFilter
                    ? "已写入统一规则文件：名字层丢包 + Steam 组服列表删行共用这条规则。"
                    : "已写入统一规则文件：仅名字层生效（组服列表不删这一行）。";
            return true;
        }

        /// <summary>从统一规则文件里删掉一条规则（连同上方的自动注释），并清掉因此变空的「仅名字层」标记段。</summary>
        private static void RemoveRuleLine(string rule)
        {
            var kept = new List<string>();
            foreach (var line in SplitLines(ReadTextShared(CustomFile)))
            {
                if (string.Equals(line.Trim(), rule, StringComparison.Ordinal))
                {
                    if (kept.Count > 0 && IsAutoNote(kept[kept.Count - 1])) kept.RemoveAt(kept.Count - 1);
                    continue;
                }
                kept.Add(line);
            }
            var outp = new List<string>();
            for (int i = 0; i < kept.Count; i++)
            {
                var t = kept[i].Trim();
                if (t.StartsWith(NameOnlyStart, StringComparison.Ordinal))
                {
                    int close = -1;
                    bool hasRule = false;
                    for (int j = i + 1; j < kept.Count; j++)
                    {
                        var tj = kept[j].Trim();
                        if (tj.StartsWith(NameOnlyEnd, StringComparison.Ordinal)) { close = j; break; }
                        if (tj.Length > 0 && !tj.StartsWith("#")) hasRule = true;
                    }
                    if (close > 0)
                    {
                        if (hasRule) for (int j = i; j <= close; j++) outp.Add(kept[j]);
                        i = close;
                        continue;
                    }
                }
                outp.Add(kept[i]);
            }
            SteamServerFilterIpBlock.SafeFile.Write(CustomFile, string.Join("\r\n", outp.ToArray()));
        }

        public static void ResetCustomFile()
        {
            SteamServerFilterIpBlock.SafeFile.Write(CustomFile, CustomHeader);
        }

        // ---- 规则档备份 / 删除 / 还原 ----
        public static string BackupProfileFile(string path)
        {
            try
            {
                Directory.CreateDirectory(BackupDir);
                // 审计：秒级时间戳在同一秒内两次备份会互相覆盖 —— 改成毫秒，已存在再补序号
                var stamp = DateTime.Now.ToString("yyyyMMdd-HHmmssfff");
                var dst = Path.Combine(BackupDir, Path.GetFileName(path) + "." + stamp + ".bak");
                int n = 1;
                while (File.Exists(dst))
                    dst = Path.Combine(BackupDir, Path.GetFileName(path) + "." + stamp + "-" + (n++) + ".bak");
                File.Copy(path, dst, true);
                return dst;
            }
            catch { return null; }
        }

        private static bool IsAutoNote(string line)
        {
            var t = line.Trim();
            return t.StartsWith("#") && t.Contains("(") && t.EndsWith(")");
        }

        /// <summary>从所有当前启用的规则档里删除这条规则；返回被修改的档名列表。</summary>
        public static List<string> DeleteRule(string rule)
        {
            var changed = new List<string>();
            foreach (var comp in ActiveComponents())
            {
                var f = Path.Combine(ProfileDir, comp + ".txt");
                if (!File.Exists(f)) continue;

                bool isCustom = string.Equals(comp, "custom", StringComparison.OrdinalIgnoreCase);
                // V-11: 这个文件不是合法 UTF-8（用户用记事本存成了 ANSI/GBK）时，
                // 按 UTF-8 读会把中文解成 U+FFFD，再整文件写回就【永久】损坏了所有中文规则。
                // 这里直接拒绝改写，让用户先把编码改回 UTF-8。
                if (!IsValidUtf8File(f))
                {
                    BrokenProfiles.Add(comp + ".txt（不是 UTF-8，已拒绝改写以免损坏）");
                    continue;
                }
                var kept = new List<string>();
                bool removed = false;
                foreach (var line in File.ReadAllLines(f, Utf8NoBom))
                {
                    if (string.Equals(line.Trim(), rule, StringComparison.Ordinal))
                    {
                        removed = true;
                        // custom 档里 RulesAdd 自己写的那行 "# 名字  (时间)" 也一并去掉。
                        // 其它档的注释是用户写的，不动。
                        if (isCustom && kept.Count > 0 && IsAutoNote(kept[kept.Count - 1]))
                            kept.RemoveAt(kept.Count - 1);
                        continue;
                    }
                    kept.Add(line);
                }
                if (!removed) continue;

                BackupProfileFile(f);
                SteamServerFilterIpBlock.SafeFile.Write(f, string.Join("\r\n", kept) + "\r\n");   // V-05 原子写
                changed.Add(comp + ".txt");
            }
            return changed;
        }

        /// <summary>V-11: 严格校验文件是不是合法 UTF-8（含 U+FFFD 也视为损坏）。</summary>
        public static bool IsValidUtf8File(string path)
        {
            try
            {
                if (!File.Exists(path)) return true;
                var bytes = File.ReadAllBytes(path);
                var strict = new UTF8Encoding(false, true);
                try { strict.GetString(bytes); }
                catch { return false; }
                var s = Encoding.UTF8.GetString(bytes);
                return s.IndexOf('\uFFFD') < 0;
            }
            catch { return false; }
        }

        /// <summary>本轮操作中被拒绝改写的规则档（编码非法），供界面提示。</summary>
        public static readonly List<string> BrokenProfiles = new List<string>();

        // ---- RPG 默认规则种子（仅首次合并统一规则文件时使用，不再提供「恢复默认」按钮） ----
        public static readonly string[] DefaultRpgLines = new string[]
        {
            "# ============================================================",
            "# 规则档 rpg  ——  RPG 类服务器（默认规则）",
            "# ============================================================",
            "# 匹配规则（引擎实际行为，已逆向确认）：",
            "#   * 每行一条 .NET 正则，逐行读入后对「服务器名」做 Regex.IsMatch 包含匹配",
            "#   * 区分大小写（无 IgnoreCase），不锚定（名字里任意位置出现即命中）",
            "#   * 空行会被跳过；完全相同的行会被去重，只算一条",
            "#   * block_rules.txt 本身【不支持注释】——'#' 开头的行也会被当成正则！",
            "#     所以注释只写在本档里，重新生成 block_rules.txt 时会自动剥掉。",
            "# ============================================================",
            "",
            "# 1) RPG 标志：覆盖 rpg / rpG / RPG 等全部 8 种大小写组合",
            "[Rr][Pp][Gg]",
            "",
            "# 2) Pure+ / Pure++ 网络",
            "[Pp][Uu][Rr][Ee]\\+",
            "",
            "# 3) Pure CN（Pure 网络的国服）",
            "[Pp][Uu][Rr][Ee] [Cc][Nn]",
            "",
            "# 4) [趣味] 系列（新版 RPG 服）",
            "[[][趣][味][]]",
            "",
            "# 5) 弑神巅峰",
            "[弑][神][巅][峰]",
            ""
        };

        // 说明：默认规则不再提供「一键恢复」按钮 —— 它们已并入统一规则文件 custom.txt，
        // 就是普通规则（可删可改）；DefaultRpgLines 只作为首次合并时的种子。
        // ---- P2-1：规则服务收敛（CLI / GUI / PowerShell 共用同一实现） ----

        public sealed class RuleValidation
        {
            public readonly List<string> Issues = new List<string>();
            public int RuleCount;
            public int DuplicateCount;
            public int MangledCount;
            public int InvalidRegexCount;
            public bool Exists;
            public bool Utf8Ok = true;
            public bool InSync;
            public bool Ok { get { return Issues.Count == 0; } }
        }

        /// <summary>校验 block_rules.txt：编码/BOM/重复/乱码/非法正则/是否与统一规则文件同步。只读，不写任何文件。</summary>
        public static RuleValidation ValidateRulesFile()
        {
            var v = new RuleValidation();
            v.Exists = File.Exists(RulesFile);
            if (!v.Exists)
            {
                v.Issues.Add("缺少 block_rules.txt（规则还没生成，运行 --rules-apply custom）");
                return v;
            }
            byte[] bytes;
            try { bytes = File.ReadAllBytes(RulesFile); }
            catch (Exception ex) { v.Issues.Add("读不了 block_rules.txt: " + ex.Message); return v; }

            v.Utf8Ok = RulesFileIsValidUtf8();
            if (!v.Utf8Ok) v.Issues.Add("block_rules.txt 不是合法 UTF-8（含非法字节或 U+FFFD 乱码；规则文件可能被存成了 ANSI/GBK）");
            if (bytes.Length >= 3 && bytes[0] == 0xEF && bytes[1] == 0xBB && bytes[2] == 0xBF)
                v.Issues.Add("block_rules.txt 带 UTF-8 BOM：第一条规则前面会多一个 U+FEFF，可能导致它失效");

            var text = Encoding.UTF8.GetString(bytes);
            if (text.Length > 0 && text[0] == '\uFEFF') text = text.Substring(1);
            var raw = SplitLines(text).Where(l => !string.IsNullOrWhiteSpace(l)).ToList();
            var distinct = OrdinalDistinct(raw);
            v.RuleCount = distinct.Count;
            v.DuplicateCount = raw.Count - distinct.Count;
            foreach (var rule in distinct)
            {
                if (RuleIsMangled(rule)) { v.MangledCount++; continue; }
                try { Regex.IsMatch("probe", rule, RegexOptions.None, RxTimeout); }
                catch
                {
                    v.InvalidRegexCount++;
                    if (v.InvalidRegexCount <= 10) v.Issues.Add("非法正则（引擎会忽略）: " + rule);
                }
            }
            if (v.MangledCount > 0) v.Issues.Add("乱码死规则 " + v.MangledCount + " 条（规则里含 U+FFFD，永远匹配不到）");
            if (v.InvalidRegexCount > 10) v.Issues.Add("另有 " + (v.InvalidRegexCount - 10) + " 条非法正则未逐条列出");

            try
            {
                var want = ReadProfileRules(GetActiveProfile());
                v.InSync = want.SequenceEqual(distinct, StringComparer.Ordinal);
            }
            catch (Exception ex) { v.InSync = false; v.Issues.Add("无法读取统一规则文件: " + ex.Message); }
            if (!v.InSync) v.Issues.Add("block_rules.txt 与统一规则文件不一致（改完规则还没重新生成，运行 --rules-apply custom）");
            return v;
        }

        /// <summary>打印校验报告；0 = 没问题，1 = 有问题。</summary>
        public static int PrintValidation()
        {
            var v = ValidateRulesFile();
            Console.WriteLine("规则文件    : " + RulesFile);
            Console.WriteLine("当前规则文件: " + GetActiveProfile());
            Console.WriteLine("生效规则    : " + v.RuleCount + " 条");
            Console.WriteLine("UTF-8 合法  : " + (v.Utf8Ok ? "是" : "否"));
            Console.WriteLine("重复行      : " + v.DuplicateCount);
            Console.WriteLine("乱码死规则  : " + v.MangledCount);
            Console.WriteLine("非法正则    : " + v.InvalidRegexCount);
            Console.WriteLine("与规则同步  : " + (v.InSync ? "是" : "否"));
            if (v.Ok) { Console.WriteLine("结果        : OK（没有发现问题）"); return 0; }
            Console.WriteLine("结果        : " + v.Issues.Count + " 个问题");
            foreach (var i in v.Issues) Console.WriteLine("  × " + i);
            return 1;
        }

        /// <summary>加一条规则到 custom 档并重新生成（GUI / CLI / PS 共用）。返回进程退出码。</summary>
        public static int AddCustomRule(string serverName, bool loose, bool useRegex, bool restart)
        {
            serverName = SteamServerFilterIpBlock.SafeFile.CleanName(serverName ?? "");
            if (serverName.Trim().Length == 0) { Console.WriteLine("× 服务器名为空，未做修改。"); return 2; }
            string rule;
            if (useRegex)
            {
                rule = serverName.Trim();
                try { Regex.IsMatch("probe", rule, RegexOptions.None, RxTimeout); }
                catch (Exception ex) { Console.WriteLine("× 非法正则: " + ex.Message); return 2; }
            }
            else rule = NewRuleFromName(serverName, loose);

            var hit = useRegex ? null : MatchedRule(serverName);
            if (hit != null)
            {
                Console.WriteLine("已经会被拦截（命中规则: " + hit + "），未重复添加。");
                return 0;
            }
            if (!AppendCustom(serverName, rule))
            {
                Console.WriteLine("规则已存在于 custom 档，未重复添加: " + rule);
                return 0;
            }
            Console.WriteLine("已加入 custom 档: " + rule);
            // 与 GUI/PS 的既有行为一致：加自定义规则后确保 custom 在启用组合里，否则重建不会包含它。
            var active = GetActiveProfile();
            if (!active.Split('+').Select(x => x.Trim()).Contains("custom", StringComparer.OrdinalIgnoreCase))
                active = active + "+custom";
            return ApplyProfile(active, restart);
        }

        /// <summary>按统一规则文件重新生成 block_rules.txt（先备份旧文件）。返回进程退出码。</summary>
        public static int ApplyProfile(string combo, bool restart)
        {
            combo = (combo ?? "").Trim();
            if (combo.Length == 0)
            {
                Console.WriteLine("× 规则文件为空。用法: --rules-apply custom（规则已统一，只有 custom 一个规则文件）");
                return 2;
            }
            var missing = new List<string>();
            foreach (var comp in combo.Split('+').Select(x => x.Trim()).Where(x => x.Length > 0))
                if (!File.Exists(Path.Combine(ProfileDir, comp + ".txt"))) missing.Add(comp + ".txt");
            if (missing.Count > 0)
            {
                Console.WriteLine("× 找不到规则文件: " + string.Join(", ", missing.ToArray()));
                Console.WriteLine("  可用: " + string.Join(", ", AvailableProfiles().ToArray()));
                return 2;
            }
            if (File.Exists(RulesFile))
            {
                var bak = BackupProfileFile(RulesFile);
                if (bak != null) Console.WriteLine("已备份旧规则: " + bak);
            }
            var cnt = ApplyCombo(combo);
            if (cnt < 0) { Console.WriteLine("× 生成被拒绝，block_rules.txt 未改动。"); return 1; }
            Console.WriteLine("已生成 block_rules.txt: " + cnt + " 条生效规则（规则文件 " + combo + "）。");
            if (restart) Console.WriteLine(RestartFilter());
            else Console.WriteLine("提示: 加 restart 参数可立即生效。");
            return 0;
        }

        /// <summary>备份当前 block_rules.txt；返回进程退出码。</summary>
        public static int BackupRules()
        {
            if (!File.Exists(RulesFile)) { Console.WriteLine("× 还没有 block_rules.txt 可备份（先 --rules-apply）。"); return 1; }
            var dst = BackupProfileFile(RulesFile);
            if (dst == null) { Console.WriteLine("× 备份失败（检查 rules-profiles/.backup 目录）。"); return 1; }
            Console.WriteLine("已备份: " + dst);
            return 0;
        }

        /// <summary>从备份恢复 block_rules.txt（先备份当前文件）。返回进程退出码。</summary>
        public static int RestoreRules(string file, bool restart)
        {
            file = (file ?? "").Trim();
            if (file.Length == 0) { Console.WriteLine("用法: --rules-restore <备份文件名或完整路径> [restart]"); return 2; }
            var src = FindBackup(file);
            if (src == null) { Console.WriteLine("× 找不到备份文件: " + file); return 2; }
            var cur = File.Exists(RulesFile) ? BackupProfileFile(RulesFile) : null;
            if (cur != null) Console.WriteLine("当前 block_rules.txt 已先备份: " + cur);
            SteamServerFilterIpBlock.SafeFile.Write(RulesFile, ReadTextShared(src));
            Console.WriteLine("已恢复 block_rules.txt ← " + Path.GetFileName(src));
            if (restart) Console.WriteLine(RestartFilter());
            else Console.WriteLine("提示: 加 restart 参数可立即生效。");
            return 0;
        }

        /// <summary>按文件名或完整路径找备份；找不到返回 null。</summary>
        public static string FindBackup(string nameOrPath)
        {
            var p = (nameOrPath ?? "").Trim();
            if (p.Length == 0) return null;
            if (File.Exists(p)) return p;
            var inDir = Path.Combine(BackupDir, p);
            return File.Exists(inDir) ? inDir : null;
        }


        // ---- 历史语料命中统计 ----
        /// <summary>从 Logs 里统计每个服务器名被拦过多少次（name -> count）。</summary>
        public static Dictionary<string, int> LoadCorpus()
        {
            var map = new Dictionary<string, int>(StringComparer.Ordinal);
            if (!Directory.Exists(LogDir)) return map;
            var rx = new Regex(@"Block server with name: (.*)$");
            foreach (var f in Directory.GetFiles(LogDir, "*.log"))
            {
                string text;
                try { text = ReadTextShared(f); } catch { continue; }
                foreach (var line in SplitLines(text))
                {
                    var m = rx.Match(line);
                    if (!m.Success) continue;
                    var n = m.Groups[1].Value;
                    int c;
                    map[n] = map.TryGetValue(n, out c) ? c + 1 : 1;
                }
            }
            return map;
        }

        public static int CountHits(string rule, Dictionary<string, int> corpus)
        {
            try
            {
                var rx = new Regex(rule, RegexOptions.None, RxTimeout);
                int sum = 0;
                foreach (var kv in corpus) if (rx.IsMatch(kv.Key)) sum += kv.Value;
                return sum;
            }
            catch { return -1; }
        }

        // ---- 过滤器进程 ----
        public static Process[] FilterProcesses()
        {
            return SteamServerFilterIpBlock.Lifecycle.Processes();
        }

        /// <summary>结束并重新启动过滤器，让它重新读取 block_rules.txt。</summary>
        public static string RestartFilter()
        {
            return SteamServerFilterIpBlock.Lifecycle.RestartLog();
        }

        public static string LastStartupInfo()
        {
            return SteamServerFilterIpBlock.Lifecycle.LastStartupInfo();
        }

        private static int _todayBlocks = -1;
        private static DateTime _todayBlocksAt = DateTime.MinValue;

        public static int TodayBlockCount()
        {
            try
            {
                // V-13: 统一界面每 1.5 秒刷新状态，这里缓存 30 秒，避免每个 tick 都全文读当天日志
                if (_todayBlocks >= 0 && (DateTime.Now - _todayBlocksAt).TotalSeconds < 30) return _todayBlocks;
                var today = Path.Combine(LogDir, DateTime.Now.ToString("yyyy-MM-dd") + ".log");
                if (!File.Exists(today)) return 0;
                _todayBlocks = Regex.Matches(ReadTextShared(today), "Block server with name:").Count;
                _todayBlocksAt = DateTime.Now;
                return _todayBlocks;
            }
            catch { return 0; }
        }
    }

    // ------------------------------------------------- 名字 -> IP 的桥接
    // 输入服务器名时，顺手查 IpBlock 的「名字↔IP」表，把对应 IP 也加进 ip_block.txt，
    // 这样即使这个服改了名字，IP 层仍然拦得住。
    internal static class IpBridge
    {
        public static string Root = AppDomain.CurrentDomain.BaseDirectory;
        public static string MapFile   { get { return Path.Combine(Root, "name_ip_map.tsv"); } }
        public static string BlockFile { get { return Path.Combine(Root, "ip_block.txt"); } }
        public static string Heartbeat { get { return Path.Combine(Root, "ip_block.heartbeat.txt"); } }
        private static readonly Encoding U8 = new UTF8Encoding(false);

        public static int MapCount()
        {
            try
            {
                if (!File.Exists(MapFile)) return 0;
                int n = 0;
                foreach (var l in File.ReadAllLines(MapFile, U8)) if (l.Trim().Length > 0) n++;
                return n;
            }
            catch { return 0; }
        }

        public static bool BlockerRunning()
        {
            try
            {
                if (!File.Exists(Heartbeat)) return false;
                foreach (var l in File.ReadAllLines(Heartbeat, U8))
                {
                    if (l.StartsWith("updated=", StringComparison.Ordinal))
                    {
                        DateTime t;
                        if (DateTime.TryParse(l.Substring(8).Trim(), out t))
                            return (DateTime.Now - t).TotalSeconds < 15;
                    }
                }
            }
            catch { }
            return false;
        }

        /// <summary>把服名解析成 IP 并追加进 ip_block.txt；返回新增的 IP。
        /// 解析逻辑统一委托给 IpEngine.ResolveSmart（含"关键词/品牌"兜底匹配）。</summary>
        public static List<string> AddIpsForName(string text, out List<string> matchedNames)
        {
            return SteamServerFilterIpBlock.IpEngine.AddNameToBlockList(text, out matchedNames);
        }

        /// <summary>只解析不写入：返回 IP 列表 + 依据说明。</summary>
        public static List<string> PreviewIps(string text, out string how, out List<string> matchedNames)
        {
            return SteamServerFilterIpBlock.IpEngine.ResolveIps(text, out how, out matchedNames);
        }

    }

    // ------------------------------------------------------------------ 界面
    internal sealed class MainForm : Form
    {
        private readonly TextBox _txtName   = new TextBox();
        private readonly Label   _lblStatus = new Label();
        private readonly RadioButton _rbExact = new RadioButton();
        private readonly RadioButton _rbLoose = new RadioButton();
        private readonly Label   _lblPreview = new Label();
        private readonly CheckBox _chkRestart = new CheckBox();
        private readonly CheckBox _chkAlsoIp = new CheckBox();
        private readonly Button  _btnAdd    = new Button();
        private readonly ListView _lvRules  = new ListView();
        private readonly Button  _btnDelete = new Button();
        private readonly Button  _btnClear  = new Button();
        private readonly Button  _btnStats  = new Button();
        private readonly Button  _btnFolder = new Button();
        private readonly Label   _lblState  = new Label();
        private readonly Button  _btnRefresh = new Button();
        private readonly Button  _btnRestart = new Button();
        private readonly TextBox _txtLog    = new TextBox();

        private static Font UiFont(float size, FontStyle style)
        {
            string[] names = { "Microsoft YaHei UI", "Microsoft YaHei", "MS Shell Dlg 2" };
            foreach (var n in names)
            {
                try { return new Font(n, size, style); } catch { }
            }
            return new Font(SystemFonts.MessageBoxFont.FontFamily, size, style);
        }

        public MainForm()
        {
            Text = "SteamServerFilter 规则添加器";
            ClientSize = new Size(900, 744);
            StartPosition = FormStartPosition.CenterScreen;
            FormBorderStyle = FormBorderStyle.FixedSingle;
            MaximizeBox = false;
            Font = UiFont(9f, FontStyle.Regular);
            Icon = TryIcon();

            // ---------------- ① 服务器名 ----------------
            var lbl1 = new Label();
            lbl1.Text = "① 粘贴要拦截的服务器名（从 L4D2 服务器浏览器里复制）";
            lbl1.Location = new Point(12, 10);
            lbl1.Size = new Size(876, 18);
            Controls.Add(lbl1);

            _txtName.Location = new Point(12, 30);
            _txtName.Size = new Size(756, 26);
            _txtName.Font = UiFont(10f, FontStyle.Regular);
            _txtName.TextChanged += (s, e) => UpdatePreview();
            Controls.Add(_txtName);

            var btnPaste = new Button();
            btnPaste.Text = "粘贴";
            btnPaste.Location = new Point(778, 30);
            btnPaste.Size = new Size(110, 26);
            btnPaste.Click += (s, e) => PasteFromClipboard();
            Controls.Add(btnPaste);

            _lblStatus.Location = new Point(12, 60);
            _lblStatus.Size = new Size(876, 20);
            Controls.Add(_lblStatus);

            // ---------------- ② 匹配方式 ----------------
            var grpMatch = new GroupBox();
            grpMatch.Text = "② 匹配方式";
            grpMatch.Location = new Point(12, 86);
            grpMatch.Size = new Size(436, 146);
            Controls.Add(grpMatch);

            _rbExact.Text = "精确：只匹配这一个完整名字（推荐）";
            _rbExact.Location = new Point(14, 22);
            _rbExact.Size = new Size(406, 22);
            _rbExact.Checked = true;
            _rbExact.CheckedChanged += (s, e) => UpdatePreview();
            grpMatch.Controls.Add(_rbExact);

            _rbLoose.Text = "数字通配：把数字当 \\d+，一并盖住同族服";
            _rbLoose.Location = new Point(14, 46);
            _rbLoose.Size = new Size(406, 22);
            _rbLoose.CheckedChanged += (s, e) => UpdatePreview();
            grpMatch.Controls.Add(_rbLoose);

            _lblPreview.Location = new Point(14, 96);
            _lblPreview.Size = new Size(410, 26);
            _lblPreview.ForeColor = Color.DimGray;
            grpMatch.Controls.Add(_lblPreview);

            // ---------------- ③ 添加 ----------------
            var grpAction = new GroupBox();
            grpAction.Text = "③ 添加";
            grpAction.Location = new Point(456, 86);
            grpAction.Size = new Size(432, 146);
            Controls.Add(grpAction);

            _chkRestart.Text = "改动后立即重启过滤器生效";
            _chkRestart.Location = new Point(14, 22);
            _chkRestart.Size = new Size(404, 22);
            _chkRestart.Checked = true;
            grpAction.Controls.Add(_chkRestart);

            _btnAdd.Text = "添加到规则";
            _btnAdd.Location = new Point(14, 50);
            _btnAdd.Size = new Size(404, 48);
            _btnAdd.Font = UiFont(12f, FontStyle.Bold);
            _btnAdd.Click += (s, e) => DoAdd();
            grpAction.Controls.Add(_btnAdd);

            _chkAlsoIp.Text = "同时按 IP 拦（自动解析该服的 IP，改名也拦得住）";
            _chkAlsoIp.Location = new Point(14, 102);
            _chkAlsoIp.Size = new Size(404, 22);
            _chkAlsoIp.Checked = true;
            grpAction.Controls.Add(_chkAlsoIp);

            // ---------------- ④ 全部规则浏览器 ----------------
            var grpRules = new GroupBox();
            grpRules.Text = "④ 全部生效规则（来自统一规则文件；选中可删除，双击可复制规则文本）";
            grpRules.Location = new Point(12, 242);
            grpRules.Size = new Size(876, 300);
            Controls.Add(grpRules);

            _lvRules.Location = new Point(14, 22);
            _lvRules.Size = new Size(848, 206);
            _lvRules.View = View.Details;
            _lvRules.FullRowSelect = true;
            _lvRules.GridLines = true;
            _lvRules.MultiSelect = true;
            _lvRules.HideSelection = false;
            _lvRules.Font = UiFont(9f, FontStyle.Regular);
            _lvRules.Columns.Add("规则（.NET 正则）", 360);
            _lvRules.Columns.Add("来源", 120);
            _lvRules.Columns.Add("历史命中", 80);
            _lvRules.Columns.Add("说明", 268);
            _lvRules.DoubleClick += (s, e) => CopySelectedRule();
            _lvRules.SelectedIndexChanged += (s, e) => UpdateDeleteButtons();
            grpRules.Controls.Add(_lvRules);

            _btnDelete.Text = "删除选中规则";
            _btnDelete.Location = new Point(14, 234);
            _btnDelete.Size = new Size(161, 34);
            _btnDelete.Click += (s, e) => DoDeleteSelected();
            grpRules.Controls.Add(_btnDelete);

            _btnClear.Text = "清除所有拦截规则";
            _btnClear.Location = new Point(185, 234);
            _btnClear.Size = new Size(161, 34);
            _btnClear.Click += (s, e) => DoClearAllRules();
            grpRules.Controls.Add(_btnClear);

            _btnStats.Text = "统计历史命中";
            _btnStats.Location = new Point(356, 234);
            _btnStats.Size = new Size(161, 34);
            _btnStats.Click += (s, e) => DoStats();
            grpRules.Controls.Add(_btnStats);

            _btnFolder.Text = "打开规则文件夹";
            _btnFolder.Location = new Point(698, 234);
            _btnFolder.Size = new Size(164, 34);
            _btnFolder.Click += (s, e) => OpenFolder();
            grpRules.Controls.Add(_btnFolder);

            // ---------------- ⑤ 状态 ----------------
            var grpState = new GroupBox();
            grpState.Text = "⑤ 状态";
            grpState.Location = new Point(12, 552);
            grpState.Size = new Size(436, 180);
            Controls.Add(grpState);

            _lblState.Location = new Point(14, 22);
            _lblState.Size = new Size(408, 96);
            grpState.Controls.Add(_lblState);

            _btnRefresh.Text = "刷新状态";
            _btnRefresh.Location = new Point(14, 118);
            _btnRefresh.Size = new Size(198, 32);
            _btnRefresh.Click += (s, e) => RefreshAll();
            grpState.Controls.Add(_btnRefresh);

            _btnRestart.Text = "重新生成并重启";
            _btnRestart.Location = new Point(224, 118);
            _btnRestart.Size = new Size(198, 32);
            _btnRestart.Click += (s, e) => DoRegenerateAndRestart();
            grpState.Controls.Add(_btnRestart);

            // ---------------- ⑥ 操作记录 ----------------
            var grpLog = new GroupBox();
            grpLog.Text = "⑥ 操作记录";
            grpLog.Location = new Point(456, 552);
            grpLog.Size = new Size(432, 180);
            Controls.Add(grpLog);

            _txtLog.Location = new Point(14, 22);
            _txtLog.Size = new Size(404, 134);
            _txtLog.Multiline = true;
            _txtLog.ReadOnly = true;
            _txtLog.ScrollBars = ScrollBars.Vertical;
            _txtLog.BackColor = Color.FromArgb(250, 250, 250);
            _txtLog.Font = UiFont(9f, FontStyle.Regular);
            grpLog.Controls.Add(_txtLog);

            Load += (s, e) =>
            {
                RefreshAll();
                Log("就绪。粘贴服务器名后点「添加到规则」；下方的规则列表可以浏览和删除全部规则。");
            };
        }

        private static Icon TryIcon()
        {
            try { return Icon.ExtractAssociatedIcon(Application.ExecutablePath); }
            catch { return null; }
        }

        private void Log(string msg)
        {
            _txtLog.AppendText("[" + DateTime.Now.ToString("HH:mm:ss") + "] " + msg + "\r\n");
        }

        private void PasteFromClipboard()
        {
            try
            {
                if (Clipboard.ContainsText())
                {
                    _txtName.Text = Clipboard.GetText().Trim();
                    _txtName.Focus();
                    _txtName.SelectionStart = _txtName.Text.Length;
                }
                else Log("剪贴板里没有文本。");
            }
            catch (Exception ex) { Log("读取剪贴板失败：" + ex.Message); }
        }

        private string CurrentRule(out string error)
        {
            error = null;
            var name = _txtName.Text.Trim();
            if (name.Length == 0) { error = "请先输入服务器名。"; return null; }
            return Engine.NewRuleFromName(name, _rbLoose.Checked);
        }

        private void UpdatePreview()
        {
            string err;
            var rule = CurrentRule(out err);
            _lblPreview.Text = (rule == null) ? "" : "将写入规则：" + rule;
            _lblPreview.ForeColor = Color.DimGray;

            var name = _txtName.Text.Trim();
            if (name.Length == 0) { _lblStatus.Text = ""; return; }

            var hit = Engine.MatchedRule(name);
            if (hit != null)
            {
                _lblStatus.Text = "✔ 当前规则已经能拦住它（命中 " + hit + "），无需再添加";
                _lblStatus.ForeColor = Color.SeaGreen;
            }
            else
            {
                _lblStatus.Text = "✘ 当前规则拦不住它 —— 可以添加";
                _lblStatus.ForeColor = Color.FromArgb(200, 100, 0);
            }
        }

        private void UpdateDeleteButtons()
        {
            _btnDelete.Text = _lvRules.SelectedItems.Count > 1
                ? ("删除选中 " + _lvRules.SelectedItems.Count + " 条")
                : "删除选中规则";
        }

        private void DoAdd()
        {
            string err;
            var rule = CurrentRule(out err);
            if (rule == null) { Log("× " + err); MessageBox.Show(this, err, "无法添加", MessageBoxButtons.OK, MessageBoxIcon.Warning); return; }

            var name = _txtName.Text.Trim();
            try
            {
                var already = Engine.MatchedRule(name);
                if (already != null)
                {
                    Log("· 已被现有规则拦住（" + already + "），跳过。");
                    MessageBox.Show(this, "这个名字已经被现有规则拦住了：\n\n" + already + "\n\n无需重复添加。",
                        "无需添加", MessageBoxButtons.OK, MessageBoxIcon.Information);
                    return;
                }

                var added = Engine.AppendCustom(name, rule);
                Log(added ? "· 已追加到统一规则文件 custom.txt：" + rule : "· custom.txt 里已有这条规则，跳过追加。");
                if (!string.IsNullOrEmpty(Engine.LastGroupFilterNote)) Log("· " + Engine.LastGroupFilterNote);

                var count = Engine.ApplyCombo("custom");
                Log("· 已重新生成 block_rules.txt：" + count + " 条生效规则（名字层与组服列表过滤共用）");

                WarnIfBroken();
                RestartIfConfigured();

                if (_chkAlsoIp.Checked) AddIpForName(name);

                _txtName.Clear();
                RefreshAll();
            }
            catch (Exception ex)
            {
                Log("× 失败：" + ex.Message);
                MessageBox.Show(this, ex.Message, "失败", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }

        /// <summary>按服名解析出 IP，并加进 IpBlock 的拦截清单。</summary>
        private void AddIpForName(string name)
        {
            try
            {
                List<string> names;
                var ips = IpBridge.AddIpsForName(name, out names);
                if (names.Count == 0)
                {
                    var n = IpBridge.MapCount();
                    Log("· 名字↔IP 表里没有『" + name + "』（表现有 " + n + " 条），本次只加了名字规则。");
                    Log("  想按 IP 一起拦：打开 FilterTool.exe → 点「扫描已知服务器」重建映射表，再回来加一次。");
                    return;
                }
                Log("· 名字匹配到 " + names.Count + " 项：" + string.Join(" | ", names.Take(4).ToArray()));
                if (ips.Count == 0)
                {
                    Log("· 对应 IP 已在 IP 拦截清单里。");
                    return;
                }
                Log("· 已同时把 IP 加入 IP 拦截清单：" + string.Join(", ", ips.ToArray()));
                Log(IpBridge.BlockerRunning()
                    ? "  IP 拦截常驻进程会在 ~5 秒内自动重载，改名也拦得住。"
                    : "  注意：IP 拦截目前没在运行（IpBlock.exe 里点「启动拦截」或勾选开机自启）。");
            }
            catch (Exception ex) { Log("· 按 IP 拦时出错：" + ex.Message); }
        }

        private void WarnIfBroken()
        {
            if (!Engine.RulesFileIsValidUtf8())
                Log("!! 警告：block_rules.txt 不是合法 UTF-8，中文规则会失效。");
            foreach (var r in Engine.ReadEngineRules())
                if (Engine.RuleIsMangled(r)) Log("!! 警告：规则含乱码字符，永远匹配不到真实服名：" + r);
        }

        private void RestartIfConfigured()
        {
            if (_chkRestart.Checked)
            {
                Log("· 正在重启过滤器 ...");
                Log(Engine.RestartFilter());
            }
            else Log("· 未重启。请点「重新生成并重启」或到托盘菜单点「重载规则」使其生效。");
        }

        private void CopySelectedRule()
        {
            if (_lvRules.SelectedItems.Count == 0) return;
            var txt = string.Join("\r\n", _lvRules.SelectedItems.Cast<ListViewItem>().Select(i => i.Text).ToArray());
            try { Clipboard.SetText(txt); Log("· 已复制规则到剪贴板：" + txt.Replace("\r\n", " | ")); }
            catch (Exception ex) { Log("× 复制失败：" + ex.Message); }
        }

        private void DoDeleteSelected()
        {
            if (_lvRules.SelectedItems.Count == 0) { Log("· 请先在列表里选中要删除的规则。"); return; }

            var entries = _lvRules.SelectedItems.Cast<ListViewItem>().Select(i => (RuleEntry)i.Tag).ToList();
            var sb = new StringBuilder();
            sb.AppendLine("确定删除下面 " + entries.Count + " 条规则吗？");
            sb.AppendLine();
            foreach (var e in entries) sb.AppendLine("  " + e.Rule + "      [" + e.Source + "]");
            sb.AppendLine();
            sb.AppendLine("删除 = 从它所属的规则档文件里移除该行（会先自动备份到 rules-profiles\\.backup\\）。");
            var warn = "\n注意：规则只有这一份统一文件（rules-profiles\\custom.txt），删掉后拦截范围会变小；\n改错了可以从 rules-profiles\\.backup\\ 里的备份恢复。";
            sb.Append(warn);

            if (MessageBox.Show(this, sb.ToString(), "删除规则", MessageBoxButtons.YesNo, MessageBoxIcon.Warning) != DialogResult.Yes) return;

            try
            {
                foreach (var e in entries)
                {
                    var changed = Engine.DeleteRule(e.Rule);
                    Log(changed.Count > 0
                        ? ("· 已从 " + string.Join(", ", changed.ToArray()) + " 删除：" + e.Rule)
                        : ("· 没找到可删除的位置：" + e.Rule));
                }
                var count = Engine.ApplyCombo(Engine.GetActiveProfile());
                Log("· 已重新生成 block_rules.txt：" + count + " 条生效规则。");
                // V-07: 与统一界面行为对齐 —— 删规则时同步释放它带来的 IP（并清掉脏关联）
                foreach (var e in entries)
                {
                    try
                    {
                        List<string> keptIps, pendNames;
                        var released = SteamServerFilterIpBlock.IpEngine.ReleaseIpsForRule(e.Rule, out keptIps, out pendNames);
                        if (released.Count > 0)
                            Log("· 已一并释放 " + released.Count + " 个 IP：" + string.Join(", ", released.ToArray()));
                        foreach (var pn in pendNames) SteamServerFilterIpBlock.IpEngine.RemovePending(pn);
                    }
                    catch (Exception ex3) { Log("× 释放关联 IP 失败：" + ex3.Message); }
                }
                WarnIfBroken();
                RestartIfConfigured();
                RefreshAll();
            }
            catch (Exception ex)
            {
                Log("× 删除失败：" + ex.Message);
                MessageBox.Show(this, ex.Message, "删除失败", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }

        /// <summary>清除所有拦截规则：统一规则文件（含默认规则，两层共用）+ IP 拦截清单 + 待解析队列。</summary>
        private void DoClearAllRules()
        {
            if (MessageBox.Show(this,
                    "清除所有拦截规则？\n\n" +
                    "会清空：\n" +
                    "  · 名字规则（rules-profiles\\custom.txt —— 名字层与组服列表过滤共用，含默认规则）\n" +
                    "  · IP 规则（ip_block.txt）\n" +
                    "  · 待解析队列（pending_resolve.tsv）\n\n" +
                    "清空之前会自动备份。",
                    "清除所有拦截规则", MessageBoxButtons.YesNo, MessageBoxIcon.Warning) != DialogResult.Yes) return;
            try
            {
                Engine.EnsureUnifiedRules();
                int ruleCount = Engine.ReadProfileRules("custom").Count;
                if (File.Exists(Engine.CustomFile)) Engine.BackupProfileFile(Engine.CustomFile);
                if (File.Exists(SteamServerFilterIpBlock.IpEngine.IpFile)) Engine.BackupProfileFile(SteamServerFilterIpBlock.IpEngine.IpFile);

                int ipCount = 0;
                try
                {
                    // 先把这些规则的关联清理掉，否则会留下脏关联
                    foreach (var r in Engine.ReadProfileRules("custom"))
                    {
                        List<string> keptIps, pendNames;
                        SteamServerFilterIpBlock.IpEngine.ReleaseIpsForRule(r, out keptIps, out pendNames);
                        foreach (var pn in pendNames) SteamServerFilterIpBlock.IpEngine.RemovePending(pn);
                    }
                    foreach (var n in SteamServerFilterIpBlock.IpEngine.ReadPending()) SteamServerFilterIpBlock.IpEngine.RemovePending(n.Name);
                    ipCount = SteamServerFilterIpBlock.IpEngine.ReadEntries().Count;
                    SteamServerFilterIpBlock.IpEngine.WriteEntries(new List<SteamServerFilterIpBlock.IpEntry>());
                    SteamServerFilterIpBlock.IpEngine.WriteLinks(new List<SteamServerFilterIpBlock.IpEngine.IpLink>());
                }
                catch (Exception ex4) { Log("× 清理 IP 规则失败：" + ex4.Message); }

                Engine.ResetCustomFile();
                var count = Engine.ApplyCombo("custom");
                Log("· 已清除所有拦截规则：名字规则 " + ruleCount + " 条、IP 规则 " + ipCount + " 条；现在 " + count + " 条生效规则。");
                Log("  旧规则已备份到 rules-profiles\\.backup\\；名字层与组服列表过滤都已清空。");
                RestartIfConfigured();
                RefreshAll();
            }
            catch (Exception ex) { Log("× 失败：" + ex.Message); }
        }

        private void DoStats()
        {
            try
            {
                Cursor = Cursors.WaitCursor;
                Log("· 正在扫描 Logs 统计历史命中次数 ...");
                Application.DoEvents();
                var corpus = Engine.LoadCorpus();
                var entries = _lvRules.Items.Cast<ListViewItem>().Select(i => (RuleEntry)i.Tag).ToList();
                foreach (var e in entries) e.Hits = Engine.CountHits(e.Rule, corpus);
                FillRuleList(entries);
                Log("· 统计完成（语料 " + corpus.Count + " 个不同服务器名）。");
            }
            catch (Exception ex) { Log("× 统计失败：" + ex.Message); }
            finally { Cursor = Cursors.Default; }
        }

        private void DoRegenerateAndRestart()
        {
            try
            {
                var count = Engine.ApplyCombo("custom");
                Log("· 已按统一规则文件重新生成：" + count + " 条生效规则。");
                WarnIfBroken();
                Log(Engine.RestartFilter());
                RefreshAll();
            }
            catch (Exception ex) { Log("× 失败：" + ex.Message); }
        }

        private void OpenFolder()
        {
            try { Process.Start(new ProcessStartInfo(Engine.Root) { UseShellExecute = true }); }
            catch (Exception ex) { Log("× 打开文件夹失败：" + ex.Message); }
        }

        private void FillRuleList(List<RuleEntry> entries)
        {
            _lvRules.BeginUpdate();
            _lvRules.Items.Clear();
            foreach (var e in entries) _lvRules.Items.Add(e.ToItem());
            _lvRules.EndUpdate();
            UpdateDeleteButtons();
        }

        private void RefreshAll()
        {
            try
            {
                Engine.EnsureCustomFile();

                List<RuleEntry> entries;
                try { entries = Engine.ReadActiveRulesDetailed(); }
                catch (Exception ex) { entries = new List<RuleEntry>(); Log("× 读取规则档失败：" + ex.Message); }
                FillRuleList(entries);

                var rules = Engine.ReadEngineRules();
                var mangled = rules.Count(Engine.RuleIsMangled);
                var procs = Engine.FilterProcesses();
                var inSync = Engine.IsRulesFileInSync();

                var sb = new StringBuilder();
                sb.AppendLine("当前规则文件：" + Engine.GetActiveProfile() + "    可用：" + string.Join(", ", Engine.AvailableProfiles().ToArray()));
                sb.AppendLine("规则条数：" + entries.Count + " 条    生效规则：" + rules.Count + " 条");
                sb.AppendLine("block_rules.txt：" + (inSync ? "与规则文件一致" : "≠ 规则文件（需点「重新生成并重启」）")
                              + "    编码：" + (Engine.RulesFileIsValidUtf8() ? "UTF-8 正常" : "异常！"));
                sb.AppendLine("乱码死规则：" + mangled + " 条");
                sb.AppendLine("过滤器：" + (procs.Length > 0 ? "运行中 PID " + string.Join(", ", procs.Select(p => p.Id.ToString()).ToArray()) : "未运行")
                              + "    今日已拦：" + Engine.TodayBlockCount() + " 次");
                _lblState.Text = sb.ToString().TrimEnd();
                _lblState.ForeColor = (mangled > 0 || !Engine.RulesFileIsValidUtf8() || !inSync) ? Color.Firebrick : Color.Black;

                UpdatePreview();
            }
            catch (Exception ex) { Log("× 刷新状态失败：" + ex.Message); }
        }
    }

    // ------------------------------------------------------------------ 入口
    // 名字规则层：由合并后的 FilterTool.exe 调用（Program.Run / MainForm 被工具箱托管）
    internal static class Program
    {
        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool AttachConsole(int dwProcessId);

        [DllImport("kernel32.dll")]
        private static extern IntPtr GetStdHandle(int nStdHandle);

        public static void InitRoot()
        {
            try { Engine.Root = Path.GetDirectoryName(Application.ExecutablePath); }
            catch { Engine.Root = AppDomain.CurrentDomain.BaseDirectory; }
            if (string.IsNullOrEmpty(Engine.Root)) Engine.Root = AppDomain.CurrentDomain.BaseDirectory;
        }

        /// <summary>名字规则层的命令行入口（由合并后的总入口分发）。</summary>
        public static int Run(string[] args)
        {
            InitRoot();
            try { Engine.EnsureUnifiedRules(); } catch { }   // 统一规则文件：幂等迁移（双保险，FilterTool.Main 已调）
            return RunCli(args);
        }

        private static void BindConsole()
        {
            // 与 FilterTool.BindConsole 同一策略：优先复用继承的 stdout 句柄（管道/重定向/CI），
            // 否则才 AttachConsole；否则外部脚本读不到 --rules/--status 的输出。
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

        private static void PrintRules()
        {
            var entries = Engine.ReadActiveRulesDetailed();
            Console.WriteLine("规则文件: " + Engine.CustomFile + "（统一规则，名字层 + 组服列表过滤共用）");
            Console.WriteLine("规则条数: " + entries.Count);
            int i = 0;
            foreach (var e in entries)
            {
                i++;
                Console.WriteLine(string.Format("{0,2}. {1,-34} [{2}]{3}", i, e.Rule, e.Source,
                    string.IsNullOrEmpty(e.Note) ? "" : "  # " + e.Note));
            }
        }

        private static IEnumerable<Control> Descendants(Control root)
        {
            foreach (Control c in root.Controls)
            {
                yield return c;
                foreach (var g in Descendants(c)) yield return g;
            }
        }

        private static int RunLayoutCheck()
        {
            var f = new MainForm();
            int issues = 0;
            var formClient = f.ClientRectangle;
            Console.WriteLine("窗体客户区: " + formClient.Width + " x " + formClient.Height);
            foreach (var c in Descendants(f))
            {
                var parent = c.Parent;
                if (parent == null) continue;
                var pr = parent.ClientRectangle;
                bool bad = c.Left < 0 || c.Top < 0 || c.Right > pr.Width || c.Bottom > pr.Height;
                if (!bad && parent == f) bad = c.Right > formClient.Width || c.Bottom > formClient.Height;
                if (bad)
                {
                    issues++;
                    Console.WriteLine(string.Format("  越界: {0,-12} \"{1}\"  bounds=({2},{3},{4},{5})  父={6} 客户区={7}x{8}",
                        c.GetType().Name, c.Text, c.Left, c.Top, c.Right, c.Bottom, parent.GetType().Name, pr.Width, pr.Height));
                }
            }
            Console.WriteLine(issues == 0 ? "布局自检通过：无控件越界。" : ("布局自检失败：" + issues + " 处越界。"));
            f.Dispose();
            return issues == 0 ? 0 : 1;
        }

        private static int RunCli(string[] args)
        {
            BindConsole();
            try
            {
                // V-19: 原来未小写化，直接跑 --DELETE 会落到"添加模式"，
                // 把字符串 --DELETE 当服务器名生成规则写进 custom.txt。
                var a0 = args[0].Trim().ToLowerInvariant();

                if (a0 == "--status" || a0 == "/status" || a0 == "-s")
                {
                    var rules = Engine.ReadEngineRules();
                    Console.WriteLine("目录        : " + Engine.Root);
                    Console.WriteLine("规则文件    : " + Engine.CustomFile + "（统一规则，名字层 + 组服列表过滤共用）");
                    Console.WriteLine("规则条数    : " + Engine.ReadActiveRulesDetailed().Count);
                    Console.WriteLine("生效规则    : " + rules.Count);
                    Console.WriteLine("与规则同步  : " + Engine.IsRulesFileInSync());
                    Console.WriteLine("UTF-8 合法  : " + Engine.RulesFileIsValidUtf8());
                    Console.WriteLine("乱码死规则  : " + rules.Count(Engine.RuleIsMangled));
                    var p = Engine.FilterProcesses();
                    Console.WriteLine("过滤器      : " + (p.Length > 0 ? "运行中 PID " + string.Join(",", p.Select(x => x.Id.ToString()).ToArray()) : "未运行"));
                    foreach (var r in rules) Console.WriteLine("   - " + r);
                    return 0;
                }

                if (a0 == "--list" || a0 == "/list") { PrintRules(); return 0; }

                if (a0 == "--delete" || a0 == "/delete")
                {
                    if (args.Length < 2) { Console.WriteLine("用法: RulesAdd.exe --delete \"<规则>\"  （用 --list 查看）"); return 2; }
                    var target = args[1];
                    var changed = Engine.DeleteRule(target);
                    if (changed.Count == 0) { Console.WriteLine("没找到这条规则，未做修改: " + target); return 1; }
                    Console.WriteLine("已从 " + string.Join(", ", changed.ToArray()) + " 删除: " + target);
                    var c = Engine.ApplyCombo(Engine.GetActiveProfile());
                    Console.WriteLine("已重新生成 block_rules.txt: " + c + " 条生效规则。");
                    if (args.Length > 2 && args[2].Trim().ToLowerInvariant() == "restart")
                    {
                        Console.WriteLine("正在重启过滤器 ...");
                        Console.WriteLine(Engine.RestartFilter());
                    }
                    else Console.WriteLine("提示: 加 restart 参数可立即生效。");
                    return 0;
                }

                if (a0 == "--check" || a0 == "/check")
                {
                    if (args.Length < 2) { Console.WriteLine("用法: RulesAdd.exe --check \"<服务器名>\""); return 2; }
                    var hit = Engine.MatchedRule(args[1]);
                    if (hit != null) { Console.WriteLine("会被拦截，命中规则: " + hit); return 0; }
                    Console.WriteLine("不会被拦截。建议规则(精确): " + Engine.NewRuleFromName(args[1], false));
                    Console.WriteLine("不会被拦截。建议规则(通配): " + Engine.NewRuleFromName(args[1], true));
                    return 1;
                }

                // ---- P2-1：规则服务收敛后的统一入口（CLI / RulesTool.ps1 共用） ----
                if (a0 == "--validate" || a0 == "--rules-validate") return Engine.PrintValidation();

                if (a0 == "--add-rule" || a0 == "--rules-add")
                {
                    if (args.Length < 2) { Console.WriteLine("用法: --rules-add \"<服务器名>\" [exact|loose|regex] [restart]"); return 2; }
                    bool looseOpt = true, useRegexOpt = false, restartOpt = false;
                    for (int i = 2; i < args.Length; i++)
                    {
                        var t = (args[i] ?? "").Trim().ToLowerInvariant();
                        if (t == "exact") looseOpt = false;
                        else if (t == "loose") looseOpt = true;
                        else if (t == "regex") useRegexOpt = true;
                        else if (t == "restart") restartOpt = true;
                        else { Console.WriteLine("× 不认识的参数: " + args[i] + "（可用 exact|loose|regex|restart）"); return 2; }
                    }
                    return Engine.AddCustomRule(args[1], looseOpt, useRegexOpt, restartOpt);
                }

                if (a0 == "--apply-profile" || a0 == "--rules-apply")
                {
                    if (args.Length < 2) { Console.WriteLine("用法: --rules-apply custom [restart]（规则已统一，只有一个规则文件）"); return 2; }
                    bool restartOpt = false;
                    for (int i = 2; i < args.Length; i++)
                    {
                        var t = (args[i] ?? "").Trim().ToLowerInvariant();
                        if (t == "restart") restartOpt = true;
                        else { Console.WriteLine("× 不认识的参数: " + args[i] + "（只有 restart）"); return 2; }
                    }
                    if (!string.Equals((args[1] ?? "").Trim(), "custom", StringComparison.OrdinalIgnoreCase))
                        Console.WriteLine("· 规则已统一：只有 rules-profiles\\custom.txt 一个规则文件，参数「" + args[1] + "」已忽略。");
                    return Engine.ApplyProfile("custom", restartOpt);
                }

                if (a0 == "--backup-rules" || a0 == "--rules-backup") return Engine.BackupRules();

                if (a0 == "--restore-rules" || a0 == "--rules-restore")
                {
                    if (args.Length < 2) { Console.WriteLine("用法: --rules-restore <备份文件名或完整路径> [restart]"); return 2; }
                    bool restartOpt = args.Length > 2 && string.Equals((args[2] ?? "").Trim(), "restart", StringComparison.OrdinalIgnoreCase);
                    return Engine.RestoreRules(args[1], restartOpt);
                }

                if (a0 == "--layout") return RunLayoutCheck();

                if (a0 == "--shot")
                {
                    var path = args.Length >= 2 ? args[1] : Path.Combine(Engine.Root, "RulesAdd-ui.png");
                    Application.EnableVisualStyles();
                    Application.SetCompatibleTextRenderingDefault(false);
                    using (var f = new MainForm())
                    {
                        f.StartPosition = FormStartPosition.Manual;
                        f.Location = new Point(-5000, -5000);
                        f.ShowInTaskbar = false;
                        f.Show();
                        for (int i = 0; i < 20; i++) { Application.DoEvents(); Thread.Sleep(25); }
                        f.Refresh();
                        Application.DoEvents();
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

                if (a0 == "--ip-for")
                {
                    if (args.Length < 2) { Console.WriteLine("用法: RulesAdd.exe --ip-for \"<服务器名或片段>\""); return 2; }
                    List<string> names;
                    var ips = IpBridge.AddIpsForName(args[1], out names);
                    if (names.Count == 0)
                    {
                        Console.WriteLine("名字↔IP 表里没有『" + args[1] + "』（表现有 " + IpBridge.MapCount() + " 条）。");
                        Console.WriteLine("先打开 IpBlock.exe 点「扫描已知服务器」重建映射表。");
                        return 1;
                    }
                    Console.WriteLine("匹配到 " + names.Count + " 项：" + string.Join(" | ", names.Take(5).ToArray()));
                    if (ips.Count == 0) { Console.WriteLine("对应 IP 已在 IP 拦截清单里。"); return 0; }
                    Console.WriteLine("已加入 IP 拦截清单：" + string.Join(", ", ips.ToArray()));
                    Console.WriteLine(IpBridge.BlockerRunning()
                        ? "IP 拦截常驻进程会在 ~5 秒内自动重载。"
                        : "注意：IP 拦截目前没在运行。");
                    return 0;
                }
                if (a0 == "--help" || a0 == "/?" || a0 == "-h")
                {
                    Console.WriteLine("SteamServerFilter 规则添加器");
                    Console.WriteLine("  RulesAdd.exe                         打开界面");
                    Console.WriteLine("  RulesAdd.exe \"<服务器名>\" [loose|regex] [restart]");
                    Console.WriteLine("  RulesAdd.exe --check \"<服务器名>\"     查是否已被拦");
                    Console.WriteLine("  RulesAdd.exe --list                  列出全部生效规则及来源");
                    Console.WriteLine("  RulesAdd.exe --delete \"<规则>\" [restart]");
                    Console.WriteLine("  RulesAdd.exe --ip-for \"<服务器名或片段>\"   按名字解析出 IP 并加进 IP 拦截清单");
                    Console.WriteLine("  RulesAdd.exe --validate              校验 block_rules.txt（编码/重复/乱码/非法正则/同步）");
                    Console.WriteLine("  RulesAdd.exe --add-rule \"<名>\" [exact|loose|regex] [restart]  加进统一规则文件并重建");
                    Console.WriteLine("  RulesAdd.exe --rules-apply custom [restart]  按统一规则文件重建 block_rules.txt");
                    Console.WriteLine("  RulesAdd.exe --backup-rules          备份当前 block_rules.txt");
                    Console.WriteLine("  RulesAdd.exe --restore-rules <备份> [restart]  从备份恢复");
                    Console.WriteLine("  RulesAdd.exe --status                查看状态");
                    Console.WriteLine("  RulesAdd.exe --layout                自检界面控件是否越界");
                    return 0;
                }

                // 添加模式
                var name = args[0];
                bool loose = true, restart = false, useRegex = false;
                for (int i = 1; i < args.Length; i++)
                {
                    var t = args[i].Trim().ToLowerInvariant();
                    if (t == "loose") loose = true;
                    else if (t == "exact") loose = false;
                    else if (t == "regex") useRegex = true;
                    else if (t == "restart") restart = true;
                }

                if (useRegex) { try { new Regex(name); } catch (Exception ex) { Console.WriteLine("非法正则: " + ex.Message); return 2; } }

                var rule = useRegex ? name : Engine.NewRuleFromName(name, loose);
                var already = useRegex ? null : Engine.MatchedRule(name);
                if (already != null)
                {
                    Console.WriteLine("已被现有规则拦住，无需添加: " + already);
                    return 0;
                }

                var added = Engine.AppendCustom(name, rule);
                Console.WriteLine((added ? "已追加规则: " : "规则已存在，跳过: ") + rule);
                if (!string.IsNullOrEmpty(Engine.LastGroupFilterNote)) Console.WriteLine("· " + Engine.LastGroupFilterNote);

                var count = Engine.ApplyCombo("custom");
                Console.WriteLine("已重新生成 block_rules.txt: " + count + " 条生效规则（统一规则文件）");

                if (restart)
                {
                    Console.WriteLine("正在重启过滤器 ...");
                    Console.WriteLine(Engine.RestartFilter());
                }
                else Console.WriteLine("提示: 加 restart 参数可立即生效，或在界面里点「重新生成并重启」。");
                return 0;
            }
            catch (Exception ex)
            {
                Console.WriteLine("错误: " + ex.Message);
                if (Environment.GetEnvironmentVariable("RULESADD_DEBUG") == "1")
                    Console.WriteLine(ex.ToString());
                return 1;
            }
        }
    }
}
