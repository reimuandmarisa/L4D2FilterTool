// ============================================================================
//  Config —— 统一开关文件 config.ini（优化方案 3.2）
//
//  背景：name_layer.txt / block_mode.txt / tray.txt / log_retention.txt 四个单值文件
//  各有"写文件 + 监视戳"一套，主循环里四组 stamp 变量。这里收敛成**一个人可读的
//  config.ini**：常驻进程只需监视一个戳。
//
//  兼容策略：读取时 config.ini 优先，没有该键就回落到旧文件；写入 config.ini。
//  旧文件保留不被删除，随时可以手编回退。
// ============================================================================

using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

namespace SteamServerFilterIpBlock
{
    internal static class Config
    {
        public static string File { get { return Path.Combine(IpEngine.Root, "config.ini"); } }

        private static readonly string[] Keys = { "name-layer", "mode", "tray", "log-keep", "active-profile",
                                                   "group-filter", "group-filter-mode", "group-filter-passthrough",
                                                   "group-filter-dedupe",
                                                   "group-filter-namelayer", "group-filter-session-token" };

        /// <summary>读一个键；不存在返回 null。</summary>
        public static string Get(string key)
        {
            try
            {
                if (!System.IO.File.Exists(File)) return null;
                foreach (var l in SafeFile.Read(File).Replace("\r\n", "\n").Split('\n'))
                {
                    var s = l.Trim();
                    if (s.Length == 0 || s.StartsWith("#") || s.StartsWith("[")) continue;
                    var eq = s.IndexOf('=');
                    if (eq <= 0) continue;
                    if (string.Equals(s.Substring(0, eq).Trim(), key, StringComparison.OrdinalIgnoreCase))
                        return s.Substring(eq + 1).Trim();
                }
            }
            catch { }
            return null;
        }

        /// <summary>写一个键（保留其它键、注释与顺序；原子写）。</summary>
        public static void Set(string key, string value)
        {
            SafeFile.WithLock(() =>
            {
                var lines = new List<string>();
                try
                {
                    if (System.IO.File.Exists(File))
                        lines.AddRange(SafeFile.Read(File).Replace("\r\n", "\n").Split('\n'));
                }
                catch { }
                if (lines.Count == 0 || (lines.Count == 1 && lines[0].Length == 0))
                {
                    lines.Clear();
                    lines.Add("# SteamServerFilter / FilterTool 统一开关（纯文本，可直接手编）");
                    lines.Add("# 改完保存即可：常驻进程 5 秒内自动重读");
                    lines.Add("");
                }
                bool done = false;
                for (int k = 0; k < lines.Count; k++)
                {
                    var s = lines[k].Trim();
                    if (s.Length == 0 || s.StartsWith("#") || s.StartsWith("[")) continue;
                    var eq = s.IndexOf('=');
                    if (eq <= 0) continue;
                    if (string.Equals(s.Substring(0, eq).Trim(), key, StringComparison.OrdinalIgnoreCase))
                    { lines[k] = key + " = " + value; done = true; break; }
                }
                if (!done) lines.Add(key + " = " + value);
                var sb = new StringBuilder();
                foreach (var l in lines) sb.Append(l).Append("\r\n");
                SafeFile.Write(File, sb.ToString());
            });
        }

        /// <summary>读布尔键：on/true/1/yes → true；off/false/0/no → false；未设置 → null。</summary>
        public static bool? GetBool(string key)
        {
            var v = Get(key);
            if (v == null) return null;
            v = v.Trim().ToLowerInvariant();
            if (v.StartsWith("on") || v.StartsWith("true") || v == "1" || v.StartsWith("yes")) return true;
            if (v.StartsWith("off") || v.StartsWith("false") || v == "0" || v.StartsWith("no")) return false;
            return null;
        }

        public static int? GetInt(string key)
        {
            var v = Get(key);
            int n;
            if (v != null && int.TryParse(v.Trim(), out n)) return n;
            return null;
        }

        /// <summary>3.2：四个开关来源合成【一个】戳 —— 常驻进程只需比一个时间。</summary>
        public static DateTime ConfigStamp()
        {
            var newest = DateTime.MinValue;
            foreach (var f in new[] { File, NameLayer.FlagFile, NameLayer.ModeFile,
                                      Path.Combine(IpEngine.Root, "tray.txt") })
            {
                try
                {
                    if (f == null || !System.IO.File.Exists(f)) continue;
                    var s = System.IO.File.GetLastWriteTime(f);
                    if (s > newest) newest = s;
                }
                catch { }
            }
            return newest;
        }
        private const string SensitiveKey = "group-filter-session-token";

        /// <summary>P2-2：键对应的旧单值文件（用于兼容读取/审计）；没有旧文件返回 null。</summary>
        private static string LegacyFileFor(string key)
        {
            switch (key)
            {
                case "name-layer": return NameLayer.FlagFile;
                case "mode": return NameLayer.ModeFile;
                case "tray": return Path.Combine(IpEngine.Root, "tray.txt");
                case "log-keep": return IpEngine.LogRetentionFile;
                case "active-profile": return SteamServerFilterRules.Engine.StateFile;
                default: return null;
            }
        }

        private static string ReadLegacyValue(string key)
        {
            try
            {
                var f = LegacyFileFor(key);
                if (f == null || !System.IO.File.Exists(f)) return null;
                // 旧文件里可能带注释行（如 " # on = ..."），审计/回退只取第一行有效值，
                // 否则会把整段注释当成"值"，和 config.ini 的 on/off 误判成冲突。
                foreach (var raw in SafeFile.Read(f).Replace("\r\n", "\n").Split('\n'))
                {
                    var s = raw.Trim();
                    if (s.Length == 0 || s.StartsWith("#")) continue;
                    return s;
                }
                return null;
            }
            catch { return null; }
        }

        public static List<string> Dump()
        {
            var o = new List<string>();
            foreach (var k in Keys)
            {
                var v = Get(k);
                if (k == SensitiveKey)
                    o.Add(k + " = " + (string.IsNullOrEmpty(v) ? "(未设置)" : "(已设置，已隐藏)"));
                else
                    o.Add(k + " = " + (v ?? "(未设置，回落到旧文件)"));
            }
            return o;
        }

        /// <summary>
        /// P2-2：统一开关审计。逐个键列出 config.ini 与旧单值文件里的取值，标出冲突与当前事实源。
        /// 会话 token 只显示"已设置/未设置"，绝不输出明文。
        /// </summary>
        public static List<string> Audit()
        {
            var o = new List<string>();
            o.Add("统一开关审计（config.ini = " + File + "）");
            o.Add("  规则：config.ini 优先；键不存在时才回落到旧单值文件；旧文件不会被删除。");
            foreach (var k in Keys)
            {
                var ini = Get(k);
                if (k == SensitiveKey)
                {
                    o.Add("  " + k.PadRight(28) + " ini=" + (string.IsNullOrEmpty(ini) ? "(未设置)" : "(已设置，已隐藏)"));
                    continue;
                }
                var legacy = ReadLegacyValue(k);
                var eff = ini ?? legacy;
                var src = ini != null ? "config.ini" : (legacy != null ? LegacyFileFor(k) : "(默认)");
                var line = "  " + k.PadRight(28) + " ini=" + (ini ?? "-") +
                           "  旧文件=" + (legacy ?? "-") + "  生效=" + (eff ?? "-") + "  来源=" + src;
                if (ini != null && legacy != null &&
                    !string.Equals(ini.Trim(), legacy.Trim(), StringComparison.OrdinalIgnoreCase))
                    line += "  ★ 冲突（以 config.ini 为准）";
                o.Add(line);
            }
            o.Add("  提示：FilterTool.exe --config-migrate 把旧文件的值迁入 config.ini（旧文件保留）。");
            return o;
        }

        /// <summary>P2-2：把五个旧开关文件的值迁移进 config.ini（旧文件保留，读取仍兼容）。</summary>
        public static List<string> Migrate()
        {
            var o = new List<string>();
            Set("name-layer", NameLayer.Enabled ? "on" : "off");
            Set("mode", NameLayer.NameOnlyMode ? "name" : "both");
            Set("tray", TrayHost.Enabled ? "on" : "off");
            Set("log-keep", IpEngine.LogRetentionDays.ToString());
            Set("active-profile", SteamServerFilterRules.Engine.GetActiveProfile());
            o.Add("已把五个旧开关写入 " + File + "（旧文件保留，读取仍兼容）");
            foreach (var l in Dump()) o.Add("  " + l);
            return o;
        }
    }
}
