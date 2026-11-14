// ============================================================================
//  SelfTest —— 核心不变量自检（优化方案 2.1）与状态收敛（2.2）
//
//  2.1 六条不变量：
//    1. 规则语义：UTF-8 无 BOM / 空行跳过 / Ordinal 去重（大小写不同算两条）/
//       大小写敏感 / 非锚定 —— Engine.ReadEngineRules 与 NameLayer.MatchRule 必须一致
//    2. A2S 解析：单包 FFFFFFFF 49 / Source 分片 FEFFFFFF + LE requestId / challenge 41
//    3. 规则生成：NewRuleFromName exact/loose 与转义
//    4. !端口 例外：TryParseRange / SplitExempt / BuildFilters / 严格 4 段 IP
//    5. 端点键往返：Key ↔ KeyToEndpoint；TryParseRange 边界 /0 /31 /32
//    6. IsPacketBlockedFastU 与 WinDivert 表达式语义一致（源/目的、多例外端口）
//
//  做法：把 Engine.Root / IpEngine.Root 指向临时目录再写样例文件，
//        **绝不触碰真实配置**，跑完恢复并让区间缓存失效。
// ============================================================================

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;

namespace SteamServerFilterIpBlock
{
    internal static class SelfTest
    {
        private static int _pass, _fail;
        private static readonly List<string> _fails = new List<string>();

        /// <summary>组服过滤是独立层：默认常开（auto 缺省 on）、监视进程的互斥体/状态文件命名固定，且不覆盖常驻进程状态。</summary>
        private static void T22_GroupFilterLayer(Action<string> log)
        {
            // 1) 没有配置键时必须常开（默认开启组服列表过滤，不再需要界面开关）
            try { File.Delete(Config.File); } catch { }
            Check(GroupServerFilter.AutoEnabled, "T22 组服过滤默认常开（无配置键）");
            Config.Set(GroupServerFilter.ConfigKeyAuto, "on");
            Check(GroupServerFilter.AutoEnabled, "T22 auto=on 时开启");
            Config.Set(GroupServerFilter.ConfigKeyAuto, "off");
            Check(!GroupServerFilter.AutoEnabled, "T22 auto=off 时关闭");

            // 2) 监视进程不靠进程名识别（避免误伤同名程序）：Local 互斥体 + groupfilter\resident.pid
            Check(GroupServerFilter.ResidentMutexName.StartsWith(@"Local\", StringComparison.Ordinal),
                  "T22 监视进程互斥体在 Local 命名空间", GroupServerFilter.ResidentMutexName);
            Check(string.Equals(Path.GetDirectoryName(GroupServerFilter.ResidentPidPath), GroupServerFilter.Dir,
                                StringComparison.OrdinalIgnoreCase),
                  "T22 resident.pid 在 groupfilter 目录", GroupServerFilter.ResidentPidPath);
            Check(string.Equals(Path.GetFileName(GroupServerFilter.ResidentStatusPath), "resident_status.txt",
                                StringComparison.OrdinalIgnoreCase),
                  "T22 监视进程状态文件是 resident_status.txt", GroupServerFilter.ResidentStatusPath);

            // 3) 监视进程把自己状态写到 resident_status.txt，不能覆盖 --run 的 last_status.txt
            Check(!string.Equals(GroupServerFilter.ResidentStatusPath, GroupServerFilter.LastStatusPath,
                                 StringComparison.OrdinalIgnoreCase),
                  "T22 两层状态文件互相独立", GroupServerFilter.ResidentStatusPath + " vs " + GroupServerFilter.LastStatusPath);
            Check(string.Equals(Path.GetFileName(GroupServerFilter.LastStatusPath), "last_status.txt", StringComparison.OrdinalIgnoreCase),
                  "T22 常驻进程状态文件仍是 last_status.txt", GroupServerFilter.LastStatusPath);

            // 4) 重复名称过滤默认开启；显式 off 才关闭
            Check(GroupServerFilter.DedupeEnabled, "T22 组服重复名称过滤默认开启（无配置键）");
            Config.Set(GroupServerFilter.ConfigKeyDedupe, "off");
            Check(!GroupServerFilter.DedupeEnabled, "T22 dedupe=off 时关闭");
            Check(GroupServerFilter.BuildIniText(true, "").Contains("dedupe_names=0"),
                  "T22 dedupe=off 写进 DLL ini");
            Config.Set(GroupServerFilter.ConfigKeyDedupe, "on");
            Check(GroupServerFilter.DedupeEnabled, "T22 dedupe=on 时开启");
            Check(GroupServerFilter.BuildIniText(true, "").Contains("dedupe_names=1"),
                  "T22 dedupe=on 写进 DLL ini");
        }

        /// <summary>「添加规则」两层同时生效：名字层 AppendCustom 会把同一个名字写进组服列表过滤规则文件，
        /// 并且生成给钩子的组服正则真的能命中这个名字（这才是“从 Steam 组服列表删行”的实际路径）。</summary>
        /// <summary>添加规则只写一份统一文件：名字层（A2S 丢包）与组服列表过滤（删行）共用同一条规则，
        /// 并且生成给钩子的组服正则真的能命中这个名字（这才是“从 Steam 组服列表删行”的实际路径）。</summary>
        private static void T23_AddRuleDualWrite(Action<string> log)
        {
            Directory.CreateDirectory(SteamServerFilterRules.Engine.ProfileDir);
            SafeFile.Write(SteamServerFilterRules.Engine.UnifiedMarker, "unified selftest\r\n");
            var savedCustom = File.Exists(SteamServerFilterRules.Engine.CustomFile) ? SafeFile.Read(SteamServerFilterRules.Engine.CustomFile) : null;
            try
            {
                SafeFile.Write(SteamServerFilterRules.Engine.CustomFile, "# 统一规则文件（测试）\r\n");
                var name = "SSF自检服" + Guid.NewGuid().ToString("N").Substring(0, 6);
                var rule = SteamServerFilterRules.Engine.NewRuleFromName(name, true);

                Check(SteamServerFilterRules.Engine.AppendCustom(name, rule), "T23 添加规则写入统一规则文件 custom.txt");
                var note = SteamServerFilterRules.Engine.LastGroupFilterNote ?? "";
                Check(note.Contains("统一规则文件"), "T23 同一次添加说明名字层与组服过滤共用", note);
                var text = SafeFile.Read(SteamServerFilterRules.Engine.CustomFile);
                Check(text.Contains(rule) && text.Contains(name), "T23 统一规则文件里有该名字的规则与注释", rule);
                Check(SteamServerFilterRules.Engine.ReadProfileRules("custom").Contains(rule),
                      "T23 名字层从同一份文件读到该规则");

                string regex, err;
                Check(GroupServerFilter.BuildRegex(out regex, out err) && regex.Length > 0, "T23 组服正则能生成", err);
                Func<string, string> byteView = s =>
                {
                    var bs = Encoding.UTF8.GetBytes(s);
                    var cs = new char[bs.Length];
                    for (int i = 0; i < bs.Length; i++) cs[i] = (char)bs[i];
                    return new string(cs);
                };
                Check(new Regex(regex).IsMatch(byteView("x" + name + "x")), "T23 组服正则命中新加的名字");
                Check(!new Regex(regex).IsMatch(byteView("51.高级多特")), "T23 新规则不误删其他服");

                // 重复添加：同一条规则不会再写一遍
                Check(!SteamServerFilterRules.Engine.AppendCustom(name, rule), "T23 重复添加返回 false");
                Check((SteamServerFilterRules.Engine.LastGroupFilterNote ?? "").Contains("已有"),
                      "T23 重复添加不再写规则", SteamServerFilterRules.Engine.LastGroupFilterNote ?? "");
                var lines = SafeFile.Read(SteamServerFilterRules.Engine.CustomFile).Replace("\r\n", "\n").Split('\n');
                Check(lines.Count(l => l.Trim() == rule) == 1, "T23 统一规则文件里只有一条该名字");

                // 取消勾选「同时加入组服列表过滤名称」：只写名字层，组服列表不删这一行
                var name2 = "SSF仅名字层" + Guid.NewGuid().ToString("N").Substring(0, 6);
                var rule2 = SteamServerFilterRules.Engine.NewRuleFromName(name2, true);
                Check(SteamServerFilterRules.Engine.AppendCustom(name2, rule2, false), "T23 不勾选组服过滤时也能添加规则");
                Check((SteamServerFilterRules.Engine.LastGroupFilterNote ?? "").Contains("仅名字层"),
                      "T23 不勾选时说明只写名字层", SteamServerFilterRules.Engine.LastGroupFilterNote ?? "");
                Check(SafeFile.Read(SteamServerFilterRules.Engine.CustomFile).Contains(SteamServerFilterRules.Engine.NameOnlyStart),
                      "T23 仅名字层规则被标记段包住");
                Check(SteamServerFilterRules.Engine.ReadProfileRules("custom").Contains(rule2),
                      "T23 仅名字层规则仍在名字层生效");
                Check(GroupServerFilter.BuildRegex(out regex, out err) && regex.Length > 0 &&
                      !new Regex(regex).IsMatch(byteView("x" + name2 + "x")),
                      "T23 仅名字层规则不进组服删行正则", err);

                // 之后勾选再添加同名：范围升级成两层共用，且不会重复两行
                Check(SteamServerFilterRules.Engine.AppendCustom(name2, rule2, true), "T23 勾选后能把规则升级为两层共用");
                var regexUp = GroupServerFilter.BuildRegex(out regex, out err) ? regex : ".*";
                Check(new Regex(regexUp).IsMatch(byteView("x" + name2 + "x")), "T23 升级后组服正则命中这条规则", err);
                var lines2 = SafeFile.Read(SteamServerFilterRules.Engine.CustomFile).Replace("\r\n", "\n").Split('\n');
                Check(lines2.Count(l => l.Trim() == rule2) == 1, "T23 升级范围后规则只有一行");
            }
            finally
            {
                if (savedCustom == null) { try { File.Delete(SteamServerFilterRules.Engine.CustomFile); } catch { } }
                else SafeFile.Write(SteamServerFilterRules.Engine.CustomFile, savedCustom);
            }
        }



        private static void Check(bool ok, string what, string detail = "")
        {
            if (ok) { _pass++; return; }
            _fail++;
            _fails.Add(what + (detail.Length > 0 ? ("  → " + detail) : ""));
        }

        private static string TempDir()
        {
            var d = Path.Combine(Path.GetTempPath(), "sst-selftest-" + Guid.NewGuid().ToString("N").Substring(0, 8));
            Directory.CreateDirectory(Path.Combine(d, "rules-profiles"));
            return d;
        }

        /// <summary>跑全部不变量自检，返回失败条数（0 = 全绿）。</summary>
        public static int Run(Action<string> log)
        {
            _pass = 0; _fail = 0; _fails.Clear();
            var realEngineRoot = SteamServerFilterRules.Engine.Root;
            var realIpRoot = IpEngine.Root;
            var oldMode = NameLayer.NameOnlyMode;
            var oldEnabled = NameLayer.Enabled;
            var dir = TempDir();
            try
            {
                SteamServerFilterRules.Engine.Root = dir;
                IpEngine.Root = dir;
                IpEngine.InvalidateRangeCache();
                NameLayer.NameOnlyMode = false;
                ClearTestBlocked();

                T1_RuleSemantics(log);
                T2_A2sParsing(log);
                T3_RuleGeneration(log);
                T4_ExemptPort(log);
                T5_KeyRoundTrip(log);
                T6_FastPathSemantics(log);
                T7_NameOnlyInvariant(log);
                T8_DeleteCleansPending(log);
                T9_EndpointSemantics(log);
                T10_ShortUdpAndModes(log);
                T11_SourceSplitCache(log);
                T12_SplitDecidePacket(log);
                T13_EndpointReconcile(log);
                T14_CapLocate(log);
                T15_GroupListDiagnostics(log);
                T16_GroupFilter(log);
                T17_WinDivertPin(log);
                T18_Lifecycle(log);
                T19_SecurityBudget(log);
                T20_ConfigSingleSource(log);
                T21_RuleService(log);
                T22_GroupFilterLayer(log);
                T23_AddRuleDualWrite(log);
                T24_SharedNameIpRepair(log);
            }
            catch (Exception ex)
            {
                _fail++;
                _fails.Add("自检本身抛异常: " + ex.Message);
            }
            finally
            {
                // setter 仍在临时 Root 下调用：只恢复内存缓存，不写真实配置。
                ClearTestBlocked();
                NameLayer.NameOnlyMode = oldMode;
                NameLayer.Enabled = oldEnabled;
                // 清理名字层内存状态仍在临时 Root 下完成，之后不再读取真实配置。
                NameLayer.LoadRules();
                NameLayer.ReloadBlocked();
                SteamServerFilterRules.Engine.Root = realEngineRoot;
                IpEngine.Root = realIpRoot;
                IpEngine.InvalidateRangeCache();
                try { Directory.Delete(dir, true); } catch { }
            }

            if (log != null)
            {
                log("核心不变量自检：" + _pass + " 项通过， " + _fail + " 项失败");
                foreach (var f in _fails) log("  FAIL  " + f);
            }
            return _fail;
        }

        // ---------------------------------------------------------------- 1
        private static void T1_RuleSemantics(Action<string> log)
        {
            // 样例：BOM 不该有；空行跳过；两条仅大小写不同必须都保留（Ordinal 去重）；重复行去重
            var lines = new[]
            {
                "[Rr][Pp][Gg]",
                "",
                "   ",
                "[Rr][Pp][Gg]",      // 与第 1 行完全相同 → 去重
                "[RR][PP][GG]",      // 仅大小写不同 → 必须【保留】（Ordinal 去重）
                "神之右手",
                "(?i)pure[ -]*l4d2"
            };
            File.WriteAllText(IpEngine.RulesFile, string.Join("\r\n", lines) + "\r\n", new UTF8Encoding(false));

            // 文件必须没有 BOM
            var head = File.ReadAllBytes(IpEngine.RulesFile).Take(3).ToArray();
            Check(!(head.Length == 3 && head[0] == 0xEF && head[1] == 0xBB && head[2] == 0xBF),
                "T1 规则文件应为 UTF-8 无 BOM");

            // 7 行样例 → 空行 2 行跳过、完全重复 1 行去重 → 4 条；两条仅大小写不同必须都留
            var read = SteamServerFilterRules.Engine.ReadEngineRules();
            Check(read.Count == 4, "T1 空行跳过 + Ordinal 去重后应为 4 条", "实际 " + read.Count);
            Check(read.Any(r => r == lines[0]) && read.Any(r => r == "[RR][PP][GG]"),
                "T1 仅大小写不同的两条都要保留", string.Join(" / ", read.ToArray()));
            Check(!read.Any(r => r.Trim().Length == 0), "T1 不应有空规则");

            // 大小写敏感 + 非锚定：引擎与名字层必须给出一致判定
            var samples = new[]
            {
                "1#無人永生RPG战役", "1#無人永生rpg战役", "神之右手服", "x神之右手", "[Pure+] L4D2",
                "[pure][12] l4d2", "纯天然", ""
            };
            var mism = new List<string>();
            foreach (var s in samples)
            {
                var byEngine = read.Any(r => SafeRegexIsMatch(r, s));
                var byLayer = NameLayer.MatchRuleWithRules(read, s) != null;
                if (byEngine != byLayer) mism.Add(s);
            }
            Check(mism.Count == 0, "T1 Engine 与 NameLayer 判定必须一致", string.Join(" | ", mism));
        }

        private static bool SafeRegexIsMatch(string rule, string text)
        {
            try { return System.Text.RegularExpressions.Regex.IsMatch(text ?? "", rule, System.Text.RegularExpressions.RegexOptions.None, TimeSpan.FromSeconds(2)); }
            catch { return false; }
        }

        // ---------------------------------------------------------------- 2
        private static void T2_A2sParsing(Action<string> log)
        {
            // Decide 用的是 NameLayer 已加载的规则集 —— 自检里必须先把临时规则喂进去
            File.WriteAllText(IpEngine.RulesFile, "[Rr][Pp][Rg]\r\n神之右手\r\n", new UTF8Encoding(false));
            NameLayer.LoadRules();
            // 合成 IP + UDP + A2S_INFO 应答：源 1.2.3.4:27015 → 目的 10.0.0.1:50000，服名 "神之右手"
            // 注意：命中一次后该端点会被记入封禁集 —— 每个用例必须用不同的源端点，
            // 否则后续用例是被"端点封禁"丢的，而不是被规则判定丢的。
            var pkt = BuildUdp("1.2.3.4", 27015, "10.0.0.1", 50000, A2sReply("神之右手"));
            Check(NameLayer.DecidePacket(pkt, pkt.Length), "T2 单包 A2S 应答命中规则应被丢");

            // 端点封禁不变量：已命中的端点，后续即使服名无害也要丢
            var sameEp = BuildUdp("1.2.3.4", 27015, "10.0.0.1", 50000, A2sReply("无关服名"));
            Check(NameLayer.DecidePacket(sameEp, sameEp.Length), "T2 已封禁端点的后续包应继续丢");

            var pkt2 = BuildUdp("1.2.3.5", 27016, "10.0.0.1", 50001, A2sReply("无关服名"));
            Check(!NameLayer.DecidePacket(pkt2, pkt2.Length), "T2 不命中规则的新端点应放行");

            var ch = BuildUdp("1.2.3.6", 27017, "10.0.0.1", 50002,
                new byte[] { 0xFF, 0xFF, 0xFF, 0xFF, (byte)'A', 1, 2, 3, 4 });
            Check(!NameLayer.DecidePacket(ch, ch.Length), "T2 challenge 包应放行");

            var split = BuildUdp("1.2.3.7", 27018, "10.0.0.1", 50003,
                SplitReply(A2sReply("神之右手"), 17, 2)[0]);
            Check(!NameLayer.DecidePacket(split, split.Length), "T2 分片首片应放行（拿不到完整服名）");

            // 非 UDP / 太短的包不应崩
            Check(!NameLayer.DecidePacket(new byte[4], 4), "T2 过短包应安全返回 false");
        }

        private static byte[] A2sReply(string name)
        {
            var nm = Encoding.UTF8.GetBytes(name);
            var payload = new byte[6 + nm.Length + 1];
            payload[0] = 0xFF; payload[1] = 0xFF; payload[2] = 0xFF; payload[3] = 0xFF;
            payload[4] = (byte)'I'; payload[5] = 17;
            Array.Copy(nm, 0, payload, 6, nm.Length);
            payload[payload.Length - 1] = 0;
            return payload;
        }

        private static byte[] BuildUdp(string srcIp, int sport, string dstIp, int dport, byte[] payload)
        {
            var p = new byte[20 + 8 + payload.Length];
            p[0] = 0x45; p[2] = (byte)(p.Length >> 8); p[3] = (byte)p.Length; p[8] = 64; p[9] = 17;
            var s = System.Net.IPAddress.Parse(srcIp).GetAddressBytes();
            var d = System.Net.IPAddress.Parse(dstIp).GetAddressBytes();
            Array.Copy(s, 0, p, 12, 4); Array.Copy(d, 0, p, 16, 4);
            p[20] = (byte)(sport >> 8); p[21] = (byte)sport;
            p[22] = (byte)(dport >> 8); p[23] = (byte)dport;
            int ulen = 8 + payload.Length;
            p[24] = (byte)(ulen >> 8); p[25] = (byte)ulen;
            Array.Copy(payload, 0, p, 28, payload.Length);
            return p;
        }

        // ---------------------------------------------------------------- 3
        private static void T3_RuleGeneration(Action<string> log)
        {
            var exact = SteamServerFilterRules.Engine.NewRuleFromName("【CN】102.纯净三方", false);
            Check(exact == @"【CN】102\.纯净三方", "T3 exact 模式应转义点号", exact);
            var loose = SteamServerFilterRules.Engine.NewRuleFromName("【CN】102.纯净三方", true);
            Check(loose == @"【CN】\d+\.纯净三方", "T3 loose 模式应把数字换成 \\d+", loose);
            var plain = SteamServerFilterRules.Engine.NewRuleFromName("神之右手", false);
            Check(plain == "神之右手", "T3 纯中文名不应被改动", plain);
            var meta = SteamServerFilterRules.Engine.NewRuleFromName(@"a+b(c)[d]{e}|f^$*?", false);
            Check(SafeRegexIsMatch(meta, @"a+b(c)[d]{e}|f^$*?"), "T3 正则元字符必须被转义后仍能匹配原串", meta);
        }

        // ---------------------------------------------------------------- 4
        private static void T4_ExemptPort(Action<string> log)
        {
            uint s, t;
            Check(IpEngine.TryParseRange("103.40.13.58", out s, out t) && s == t && IpEngine.UintToIp(s) == "103.40.13.58",
                "T4 单地址解析");
            Check(!IpEngine.TryParseRange("103.40.13", out s, out t), "T4 缩写 IP（103.40.13）必须被拒");
            Check(!IpEngine.TryParseRange("103.40.13.999", out s, out t), "T4 越界八位组必须被拒");

            string addr; List<int> ex;
            IpEngine.SplitExempt("103.40.13.58!33030", out addr, out ex);
            Check(addr == "103.40.13.58" && ex.Count == 1 && ex[0] == 33030, "T4 !端口 拆分");
            IpEngine.SplitExempt("103.40.13.58!33030,32022", out addr, out ex);
            Check(ex.Count == 2 && ex.Contains(33030) && ex.Contains(32022), "T4 多例外端口拆分");

            var entries = new List<IpEntry> { new IpEntry { Address = "103.40.13.58!33030" } };
            var f = Blocker.BuildFilters(entries);
            Check(f.Count == 1 && f[0].Contains("udp.DstPort != 33030") && f[0].Contains("udp.SrcPort != 33030"),
                "T4 过滤器表达式应含双向例外端口", f.Count > 0 ? f[0] : "");
            var f2 = Blocker.BuildFilters(entries, true);
            Check(f2.Count == 1 && f2[0].Contains("not udp"), "T4 排除 udp 时表达式应带 not udp", f2.Count > 0 ? f2[0] : "");
        }

        // ---------------------------------------------------------------- 5
        private static void T5_KeyRoundTrip(Action<string> log)
        {
            foreach (var ep in new[] { "1.2.3.4:27015", "255.255.255.255:65535", "0.0.0.0:1", "103.40.13.58:33030" })
            {
                var c = ep.LastIndexOf(':');
                var k = NameLayer.Key(ep.Substring(0, c), int.Parse(ep.Substring(c + 1)));
                Check(k != 0 && NameLayer.KeyToEndpoint(k) == ep, "T5 端点键往返 " + ep, NameLayer.KeyToEndpoint(k));
            }
            uint s, t;
            IpEngine.TryParseRange("0.0.0.0/0", out s, out t);
            Check(s == 0 && t == 0xFFFFFFFF, "T5 /0 边界");
            IpEngine.TryParseRange("10.0.0.0/31", out s, out t);
            Check(t - s == 1, "T5 /31 边界应含 2 个地址");
            IpEngine.TryParseRange("10.0.0.1/32", out s, out t);
            Check(s == t && IpEngine.UintToIp(s) == "10.0.0.1", "T5 /32 边界");
        }

        // ---------------------------------------------------------------- 6
        private static void T6_FastPathSemantics(Action<string> log)
        {
            File.WriteAllText(IpEngine.IpFile, string.Join("\r\n", new[]
            {
                "103.40.13.58!33030",
                "10.0.0.0/24",
                "192.168.5.5"
            }) + "\r\n", new UTF8Encoding(false));
            IpEngine.InvalidateRangeCache();

            Check(IpEngine.IsPacketBlockedFast("103.40.13.58", 33026, "1.1.1.1", 5000), "T6 源命中且端口非例外 → 拦");
            Check(!IpEngine.IsPacketBlockedFast("103.40.13.58", 33030, "1.1.1.1", 5000), "T6 源端口=例外端口 → 放行");
            Check(!IpEngine.IsPacketBlockedFast("103.40.13.58", 27015, "1.1.1.1", 33030), "T6 目的端口=例外端口 → 放行（双向例外）");
            Check(IpEngine.IsPacketBlockedFast("1.1.1.1", 5000, "10.0.0.7", 27015), "T6 目的命中 CIDR → 拦");
            Check(IpEngine.IsPacketBlockedFast("192.168.5.5", 1, "1.1.1.1", 2), "T6 源命中单地址 → 拦");
            Check(!IpEngine.IsPacketBlockedFast("8.8.8.8", 53, "1.1.1.1", 5000), "T6 都不命中 → 放行");
        }

        // ---------------------------------------------------------------- 7
        /// <summary>
        /// 不变量：纯名字模式 ⇒ 名字层必须启用。
        /// 背景：界面曾出现"名字层自己拦"能取消、但常驻进程在纯名字模式下仍会拉起名字层的矛盾
        /// （用户看到的开关不起作用）。现在这条约束落在 NameLayer.NameOnlyMode 的 setter 里，
        /// 这里把它固化成断言；以后再有人绕过 setter 直接改字段，门禁会红。
        /// </summary>
        private static void T7_NameOnlyInvariant(Action<string> log)
        {
            var oldEnabled = NameLayer.Enabled;
            var oldMode = NameLayer.NameOnlyMode;
            try
            {
                NameLayer.NameOnlyMode = true;
                Check(NameLayer.Enabled, "T7 纯名字模式必须自动启用名字层（Enabled 应为 true）");
                Check(NameLayer.NameOnlyMode, "T7 模式写入后应能读回 name");
                Check(Config.Get("mode") == "name", "T7 config.ini 的 mode 应为 name", Config.Get("mode") ?? "(null)");

                NameLayer.NameOnlyMode = false;
                Check(!NameLayer.NameOnlyMode, "T7 切回 both 后应能读回 both");
                Check(NameLayer.Enabled, "T7 切回 both 不应把名字层关掉（用户没关它）");

                // 反向联动：关掉名字层 ⇒ 必须自动退出「只启动名字层」，否则会出现
                // "模式=只启动名字层、名字层=关" 的矛盾状态（界面与 CLI 共用这条约束）
                NameLayer.NameOnlyMode = true;
                NameLayer.Enabled = false;
                Check(!NameLayer.NameOnlyMode, "T7 关掉名字层必须自动退出「只启动名字层」");
                Check(Config.Get("mode") == "both", "T7 联动后 config.ini 的 mode 应为 both", Config.Get("mode") ?? "(null)");
            }
            finally
            {
                NameLayer.NameOnlyMode = oldMode;
                NameLayer.Enabled = oldEnabled;
            }
        }

        // ---------------------------------------------------------------- 8
        /// <summary>
        /// 不变量：删规则必须把它的待解析条目一起清掉（不管它有没有 IP 关联）。
        /// 踩过的坑：`--delete` 原先只清 `ReleaseIpsForRule` 返回的 pending ——
        /// 而"加了规则、没解析出 IP"的条目根本不在那个返回值里，于是留成孤儿，
        /// 工具之后每 5 分钟还徒劳地扫它一次（实测在 pending_resolve.tsv 里躺了 3 小时）。
        /// </summary>
        private static void T8_DeleteCleansPending(Action<string> log)
        {
            var before = IpEngine.ReadPending();
            try
            {
                IpEngine.AddPending("自检临时服名A", "自检临时规则A");
                Check(IpEngine.ReadPending().Any(x => x.Rule == "自检临时规则A"), "T8 前置：pending 里应有这条");

                var n = IpEngine.RemovePendingByRule("自检临时规则A");
                Check(n == 1, "T8 RemovePendingByRule 应清掉 1 条", "实际 " + n);
                Check(!IpEngine.ReadPending().Any(x => x.Rule == "自检临时规则A"), "T8 清完不应再有该规则");

                Check(IpEngine.RemovePendingByRule("不存在的规则XYZ") == 0, "T8 清不存在的规则应返回 0 且不报错");
            }
            finally
            {
                IpEngine.RemovePendingByRule("自检临时规则A");
            }
        }

        private static uint IpU(string ip)
        {
            uint a, b;
            if (!IpEngine.TryParseRange(ip, out a, out b)) throw new ArgumentException(ip);
            return a;
        }

        private static void ClearTestBlocked()
        {
            File.WriteAllText(NameLayer.BlockedFile, "", new UTF8Encoding(false));
            NameLayer.ReloadBlocked();
            NameLayer.LoadRules(); // 同时清掉尚未完成的 Source split 会话
            NameLayer.ResetPacketTestState(); // 清掉样例 seen/blocked 与待写标记，绝不启动拦截
            IpEngine.InvalidateRangeCache();
        }

        // ---------------------------------------------------------------- 9
        private static void T9_EndpointSemantics(Action<string> log)
        {
            string ip; int port;
            foreach (var s in new[] { "103.40.13.58:1", "103.40.13.58:27015", "255.255.255.255:65535", "0.0.0.0:1", "103.40.13.58:027015" })
                Check(IpEngine.TryParseEndpoint(s, out ip, out port) && IpEngine.IsValidAddress(s), "T9 合法 endpoint " + s);
            foreach (var s in new[] { "103.40.13.58:0", "103.40.13.58:65536", "103.40.13.58:-1", "103.40.13.58:x", "103.40.13.58:",
                "103.40.13.58/24:27015", "103.40.13.58:27015/24", "103.40.13.58:27015!x", "103.40.13.58:27015!27016", "103.40.13:27015", "127.1:27015", "103.40.13.999:27015", "::1:27015" })
                Check(!IpEngine.TryParseEndpoint(s, out ip, out port) && !IpEngine.IsValidAddress(s), "T9 非法 endpoint " + s);
            foreach (var s in new[] { "103.40.13.58", "103.40.13.0/24", "103.40.13.58!33030,32022" })
                Check(IpEngine.IsValidAddress(s) && !IpEngine.TryParseEndpoint(s, out ip, out port), "T9 保留 IP/CIDR/例外语法 " + s);

            var entries = new List<IpEntry>();
            Check(IpEngine.UpsertEntry(entries, "103.40.13.58:27015", "a") == "added", "T9 加入 endpoint");
            Check(IpEngine.UpsertEntry(entries, "103.40.13.58:27016", "b") == "added", "T9 同 IP 不同端口共存");
            Check(IpEngine.UpsertEntry(entries, "103.40.13.58", "c") == "added", "T9 裸 IP 与 endpoint 共存");
            Check(IpEngine.UpsertEntry(entries, "103.40.13.58:027015", "updated") == "updated" && entries.Count == 3 && entries[0].Note == "updated", "T9 同 endpoint 规范化更新");
            Check(IpEngine.SameBaseAddress(entries[0].Address, "103.40.13.58:027015"), "T9 同 endpoint identity");
            Check(!IpEngine.SameBaseAddress(entries[0].Address, entries[1].Address), "T9 不同端口 identity 独立");
            Check(!IpEngine.SameBaseAddress(entries[0].Address, entries[2].Address) && !IpEngine.SameBaseAddress(entries[2].Address, entries[0].Address), "T9 裸 IP 与 endpoint 双向独立");
            Check(IpEngine.SameBaseAddress("103.40.13.58!33030", "103.40.13.58"), "T9 例外仍共享裸 IP identity");
            foreach (var target in new[] { "103.40.13.58:27015", "103.40.13.58:27016", "103.40.13.58" })
            {
                var kept = entries.Where(e => !IpEngine.SameBaseAddress(e.Address, target)).ToList();
                Check(kept.Count == 2 && kept.All(e => e.Address != target), "T9 delete 只移除独立条目 " + target);
            }

            var filter = Blocker.BuildFilters(new List<IpEntry> { new IpEntry { Address = "103.40.13.58:27015" } });
            string f = filter.Count == 1 ? filter[0] : "";
            Check(f.Contains("udp and") && f.Contains("ip.SrcAddr == 103.40.13.58 and udp.SrcPort == 27015") && f.Contains("ip.DstAddr == 103.40.13.58 and udp.DstPort == 27015"), "T9 BuildFilters UDP only 且端口与同侧 IP 绑定", f);
            Check(!f.Contains("ip.SrcAddr == 103.40.13.58 and udp.DstPort") && !f.Contains("ip.DstAddr == 103.40.13.58 and udp.SrcPort"), "T9 BuildFilters 不交叉绑定");
            var excluded = Blocker.BuildFilters(new List<IpEntry> { new IpEntry { Address = "103.40.13.58:27015" } }, true);
            Check(excluded.Count == 0 || excluded.All(x => x.Contains("not udp")), "T9 排除 UDP 后 endpoint 不影响 TCP");

            File.WriteAllText(IpEngine.IpFile, "103.40.13.58:27015\r\n", new UTF8Encoding(false));
            IpEngine.InvalidateRangeCache();
            var ranges = IpEngine.ParsedRanges();
            Check(ranges.Length == 1 && ranges[0].Endpoint && ranges[0].Port == 27015 && ranges[0].Start == IpU("103.40.13.58") && ranges[0].Start == ranges[0].End && ranges[0].Exempt.Length == 0, "T9 ParsedRanges 保存 endpoint 元数据");
            EndpointCase("103.40.13.58", 27015, "10.0.0.1", 50000, true, "应答");
            EndpointCase("10.0.0.1", 50000, "103.40.13.58", 27015, true, "请求");
            EndpointCase("103.40.13.58", 27016, "10.0.0.1", 50000, false, "其它服务端口");
            EndpointCase("103.40.13.59", 27015, "10.0.0.1", 50000, false, "其它服务器 IP");
            EndpointCase("103.40.13.58", 27016, "10.0.0.1", 27015, false, "本机相同端口不交叉误拦");
            EndpointCase("10.0.0.1", 27015, "103.40.13.58", 27016, false, "反方向本机相同端口不误拦");
        }

        private static void EndpointCase(string src, int sport, string dst, int dport, bool expected, string what)
        {
            bool slow = IpEngine.IsPacketBlocked(src, sport, dst, dport);
            bool fast = IpEngine.IsPacketBlockedFast(src, sport, dst, dport);
            bool fastU = IpEngine.IsPacketBlockedFastU(IpU(src), sport, IpU(dst), dport);
            Check(slow == expected && fast == expected && fastU == expected, "T9 slow/fast/fastU " + what, slow + "/" + fast + "/" + fastU);
        }

        // ---------------------------------------------------------------- 10
        private static void T10_ShortUdpAndModes(Action<string> log)
        {
            var oldMode = NameLayer.NameOnlyMode;
            try
            {
                ClearTestBlocked();
                File.WriteAllText(IpEngine.IpFile, "203.0.113.10:27015\r\n", new UTF8Encoding(false));
                IpEngine.InvalidateRangeCache();
                foreach (bool nameOnly in new[] { false, true })
                {
                    NameLayer.NameOnlyMode = nameOnly;
                    for (int n = 0; n <= 4; n++)
                    {
                        var p = BuildUdp("203.0.113.10", 27015, "192.0.2.1", 50000, new byte[n]);
                        Check(NameLayer.DecidePacket(p, p.Length) == !nameOnly, "T10 短 UDP " + n + " 字节 mode=" + (nameOnly ? "name" : "both"));
                        var req = BuildUdp("192.0.2.1", 50000, "203.0.113.10", 27015, new byte[n]);
                        Check(NameLayer.DecidePacket(req, req.Length) == !nameOnly, "T10 短 UDP 请求 " + n + " mode=" + nameOnly);
                    }
                }
                NameLayer.NameOnlyMode = false;
                var other = BuildUdp("203.0.113.10", 27016, "192.0.2.1", 27015, new byte[0]);
                Check(!NameLayer.DecidePacket(other, other.Length), "T10 短包本机同端口不误拦");
                var tcp = BuildUdp("203.0.113.10", 27015, "192.0.2.1", 50000, new byte[0]); tcp[9] = 6;
                Check(!NameLayer.DecidePacket(tcp, tcp.Length), "T10 endpoint 不拦 TCP");
                NameLayer.NameOnlyMode = true;
                File.WriteAllText(IpEngine.RulesFile, "SELFTEST-BLOCK\r\n", new UTF8Encoding(false));
                ClearTestBlocked();
                var hit = BuildUdp("203.0.113.11", 27015, "192.0.2.1", 50000, A2sReply("SELFTEST-BLOCK"));
                Check(NameLayer.DecidePacket(hit, hit.Length), "T10 name 模式仍执行名字规则");
                var banned = BuildUdp("203.0.113.11", 27015, "192.0.2.1", 50000, new byte[0]);
                Check(NameLayer.DecidePacket(banned, banned.Length), "T10 已封禁 endpoint 的空 UDP 应丢");
                var bannedRequest = BuildUdp("192.0.2.1", 50000, "203.0.113.11", 27015, new byte[1]);
                Check(NameLayer.DecidePacket(bannedRequest, bannedRequest.Length), "T10 名字封禁短请求双向生效");

                Check(!NameLayer.DecidePacket(null, 28), "T10 null 安全返回");
                Check(!NameLayer.DecidePacket(new byte[28], -1), "T10 负捕获长度安全返回");
                Check(!NameLayer.DecidePacket(hit, hit.Length + 1), "T10 捕获长度超过数组安全返回");
                Check(!NameLayer.DecidePacket(hit, 27), "T10 UDP 头被截断安全返回");
                var fresh = BuildUdp("203.0.113.12", 27015, "192.0.2.1", 50000, A2sReply("SELFTEST-BLOCK"));
                var bad = (byte[])fresh.Clone(); bad[0] = 0x44;
                Check(!NameLayer.DecidePacket(bad, bad.Length), "T10 IHL 小于 20 拒绝解析");
                bad = (byte[])fresh.Clone(); bad[2] = 0xFF; bad[3] = 0xFF;
                Check(!NameLayer.DecidePacket(bad, bad.Length), "T10 IP 声明总长超过捕获拒绝解析");
                bad = (byte[])fresh.Clone(); bad[2] = 0; bad[3] = 27;
                Check(!NameLayer.DecidePacket(bad, bad.Length), "T10 IP 总长不足 UDP 头拒绝解析");
                foreach (int flag in new[] { 0x2000, 0x0001, 0x8000 })
                {
                    bad = (byte[])fresh.Clone(); bad[6] = (byte)(flag >> 8); bad[7] = (byte)flag;
                    Check(!NameLayer.DecidePacket(bad, bad.Length), "T10 IPv4 分片/保留位拒绝 " + flag);
                }
                bad = (byte[])fresh.Clone(); bad[24] = 0; bad[25] = 7;
                Check(!NameLayer.DecidePacket(bad, bad.Length), "T10 UDP 长度小于头拒绝解析");
                bad = (byte[])fresh.Clone(); bad[24] = 0xFF; bad[25] = 0xFF;
                Check(!NameLayer.DecidePacket(bad, bad.Length), "T10 UDP 长度超过 IP 拒绝解析");
                bad = (byte[])fresh.Clone(); bad[24] = 0; bad[25] = 8;
                Check(!NameLayer.DecidePacket(bad, bad.Length), "T10 不解析 UDP 声明长度外的尾部 A2S");
                var big = BuildUdp("203.0.113.13", 27015, "192.0.2.1", 50000, A2sReply("SELFTEST-BLOCK" + new string('x', 300)));
                Check(((big[2] << 8) | big[3]) == big.Length && NameLayer.DecidePacket(big, big.Length), "T10 大于 255 字节 IP 总长正确且可解析");
            }
            finally { ClearTestBlocked(); NameLayer.NameOnlyMode = oldMode; }
        }

        // Source UDP split: FE FF FF FF, requestId LE, total, index, size LE.
        private static byte[] SplitPart(uint requestId, int total, int index, int size, byte[] body)
        {
            var b = new byte[12 + body.Length];
            b[0] = 0xFE; b[1] = b[2] = b[3] = 0xFF;
            for (int i = 0; i < 4; i++) b[4 + i] = (byte)(requestId >> (8 * i));
            b[8] = (byte)total; b[9] = (byte)index;
            b[10] = (byte)size; b[11] = (byte)(size >> 8);
            Array.Copy(body, 0, b, 12, body.Length);
            return b;
        }

        private static byte[][] SplitReply(byte[] reply, uint requestId, int total)
        {
            int size = (reply.Length + total - 1) / total;
            var parts = new byte[total][];
            for (int i = 0; i < total; i++)
                parts[i] = SplitPart(requestId, total, i, size, reply.Skip(i * size).Take(size).ToArray());
            return parts;
        }

        private static byte[] Feed(NameLayer.SourceSplitCache cache, byte[] payload)
        {
            return cache.Feed(IpU("203.0.113.30"), 27015, IpU("192.0.2.1"), 50000, payload, 0, payload.Length);
        }

        // ---------------------------------------------------------------- 11
        private static void T11_SourceSplitCache(Action<string> log)
        {
            long now = 0;
            var cache = new NameLayer.SourceSplitCache(() => now);
            var reply = A2sReply("SELFTEST-BLOCK" + new string('x', 100));
            var parts = SplitReply(reply, 0x01020304, 3);
            Check(parts[0][4] == 4 && parts[0][5] == 3 && parts[0][6] == 2 && parts[0][7] == 1, "T11 requestId little endian 样例");
            Check(Feed(cache, parts[0]) == null && cache.SessionCount == 1 && cache.CachedBytes > 0, "T11 缺片保留会话但不返回");
            int bytes = (int)cache.CachedBytes;
            Check(Feed(cache, parts[0]) == null && cache.CachedBytes == bytes, "T11 相同重复片不增加缓存");
            Check(Feed(cache, parts[1]) == null, "T11 未收齐不返回");
            var joined = Feed(cache, parts[2]);
            Check(joined != null && joined.SequenceEqual(reply) && cache.SessionCount == 0 && cache.CachedBytes == 0, "T11 完整重组且释放缓存");
            Check(Feed(cache, parts[2]) == null && Feed(cache, parts[0]) == null, "T11 乱序缺片不返回");
            joined = Feed(cache, parts[1]);
            Check(joined != null && joined.SequenceEqual(reply), "T11 乱序按 index 拼接");
            cache.Clear();
            var padded = new byte[parts[0].Length + 10]; Array.Copy(parts[0], 0, padded, 5, parts[0].Length);
            Check(cache.Feed(IpU("203.0.113.30"), 27015, IpU("192.0.2.1"), 50000, padded, 5, parts[0].Length) == null && cache.SessionCount == 1, "T11 Feed 支持 offset/length");
            cache.Clear();

            // 同服务器、客户端和 requestId 中任一分量变化都必须隔离。
            var pair = SplitReply(reply, 11, 2);
            Feed(cache, pair[0]);
            foreach (int variant in Enumerable.Range(0, 5))
            {
                cache.Clear(); Feed(cache, pair[0]);
                var second = variant == 4 ? SplitReply(reply, 12, 2)[1] : pair[1];
                var result = cache.Feed(IpU(variant == 0 ? "203.0.113.31" : "203.0.113.30"), variant == 1 ? 27016 : 27015,
                    IpU(variant == 2 ? "192.0.2.2" : "192.0.2.1"), variant == 3 ? 50001 : 50000, second, 0, second.Length);
                Check(result == null && cache.SessionCount == 2, "T11 隔离 srcIp/srcPort/dstIp/dstPort/reqId 分量 " + variant);
                result = Feed(cache, pair[1]);
                Check(result != null && result.SequenceEqual(reply), "T11 隔离后原会话仍可完成 " + variant);
            }
            cache.Clear();
            Feed(cache, pair[0]); now = 1999; cache.Prune();
            Check(cache.SessionCount == 1, "T11 TTL 2s 前仍缓存");
            now = 2001; cache.Prune();
            Check(cache.SessionCount == 0 && cache.CachedBytes == 0, "T11 TTL 2s 过期释放（注入时钟，无 sleep）");
            Check(Feed(cache, pair[1]) == null, "T11 过期缺片不能重组旧响应");
            cache.Clear(); now = 0;

            var invalid = new List<byte[]> { new byte[11], SplitPart(1, 0, 0, 10, new byte[1]), SplitPart(1, 33, 0, 10, new byte[1]),
                SplitPart(1, 2, 2, 10, new byte[1]), SplitPart(0x80000001, 2, 0, 10, new byte[1]), SplitPart(1, 2, 0, 10, new byte[11]) };
            var header = (byte[])pair[0].Clone(); header[0] = 0xFF; invalid.Add(header);
            foreach (var p in invalid)
            {
                cache.Clear();
                Check(Feed(cache, p) == null && cache.SessionCount == 0 && cache.CachedBytes == 0, "T11 非法头/片数/索引/压缩/size 拒绝 " + string.Join("-", p.Take(12).Select(x => x.ToString("X2")).ToArray()));
            }
            Check(cache.Feed(1, 1, 2, 2, null, 0, 0) == null, "T11 null payload 安全返回");
            Check(cache.Feed(1, 1, 2, 2, pair[0], -1, pair[0].Length) == null, "T11 非法 offset 安全返回");
            Check(cache.Feed(1, 1, 2, 2, pair[0], 0, pair[0].Length + 1) == null, "T11 越界 length 安全返回");
            cache.Clear(); Feed(cache, pair[0]);
            var conflict = (byte[])pair[0].Clone(); conflict[12] ^= 1;
            Check(Feed(cache, conflict) == null && cache.SessionCount == 0 && cache.CachedBytes == 0, "T11 同 index 内容冲突丢弃会话");
            Feed(cache, pair[0]);
            conflict = (byte[])pair[1].Clone(); conflict[8] = 3;
            Check(Feed(cache, conflict) == null && cache.SessionCount == 0, "T11 total 冲突丢弃会话");
            Feed(cache, pair[0]);
            conflict = (byte[])pair[1].Clone(); conflict[10]--;
            Check(Feed(cache, conflict) == null && cache.SessionCount == 0, "T11 size 上限不足丢弃会话");
            cache.Clear();

            var boundary = new byte[65536];
            boundary[0] = boundary[1] = boundary[2] = boundary[3] = 0xFF; boundary[4] = 0x49;
            boundary[5] = 17; boundary[6] = (byte)'B'; boundary[7] = 0;
            var many = SplitReply(boundary, 99, 32);
            for (int i = 0; i < 31; i++) Check(Feed(cache, many[i]) == null, "T11 32片/64KiB 边界未齐 " + i);
            joined = Feed(cache, many[31]);
            Check(joined != null && joined.SequenceEqual(boundary) && cache.CachedBytes == 0, "T11 32片/64KiB 边界可完整重组");
            var oversizedReply = new byte[65537];
            oversizedReply[0] = oversizedReply[1] = oversizedReply[2] = oversizedReply[3] = 0xFF; oversizedReply[4] = 0x49;
            var oversized = SplitReply(oversizedReply, 100, 32);
            bool emitted = false;
            foreach (var p in oversized) emitted |= Feed(cache, p) != null;
            Check(!emitted && cache.CachedBytes <= 65536, "T11 超过 64KiB 单会话不返回且有界");
            cache.Clear();
            for (uint id = 1; id <= 300; id++)
            {
                Feed(cache, SplitPart(id, 2, 0, 1, new byte[1]));
                Check(cache.SessionCount <= 256 && cache.CachedBytes <= 4 * 1024 * 1024, "T11 会话上限 256 " + id);
            }
            Check(cache.SessionCount > 0, "T11 会话容量测试确实缓存了数据");
            cache.Clear();
            var large = new byte[49152];
            for (uint id = 1; id <= 100; id++)
            {
                Feed(cache, SplitPart(id, 2, 0, large.Length, large));
                Check(cache.CachedBytes <= 4 * 1024 * 1024 && cache.SessionCount <= 256, "T11 总内存上限 4MiB " + id);
            }
            Check(cache.CachedBytes > 0, "T11 内存容量测试确实缓存了数据");
            cache.Clear();
            Check(cache.SessionCount == 0 && cache.CachedBytes == 0, "T11 Clear 释放全部会话/字节");
        }

        // ---------------------------------------------------------------- 12
        private static void T12_SplitDecidePacket(Action<string> log)
        {
            var oldMode = NameLayer.NameOnlyMode;
            try
            {
                File.WriteAllText(IpEngine.IpFile, "", new UTF8Encoding(false));
                File.WriteAllText(IpEngine.RulesFile, "SELFTEST-BLOCK\r\n", new UTF8Encoding(false));
                NameLayer.NameOnlyMode = true;
                ClearTestBlocked();
                var parts = SplitReply(A2sReply("SELFTEST-BLOCK" + new string('x', 300)), 0x10203040, 3);
                foreach (int index in new[] { 2, 0, 0 })
                {
                    var p = BuildUdp("203.0.113.40", 27015, "192.0.2.1", 50000, parts[index]);
                    Check(!NameLayer.DecidePacket(p, p.Length), "T12 缺片/乱序/重复先放行 " + index);
                }
                var last = BuildUdp("203.0.113.40", 27015, "192.0.2.1", 50000, parts[1]);
                Check(NameLayer.DecidePacket(last, last.Length), "T12 最后片完整重组命中名字应丢");
                Check(NameLayer.BlockedList().Any(x => x.Key == "203.0.113.40:27015"), "T12 重组命中记录服务器 endpoint");
                var request = BuildUdp("192.0.2.1", 50000, "203.0.113.40", 27015, new byte[0]);
                Check(NameLayer.DecidePacket(request, request.Length), "T12 重组封禁后短请求也丢");
                var otherPort = BuildUdp("203.0.113.40", 27016, "192.0.2.1", 27015, new byte[0]);
                Check(!NameLayer.DecidePacket(otherPort, otherPort.Length), "T12 名字封禁不连坐其它服务端口");
                ClearTestBlocked();
                var pair = SplitReply(A2sReply("SELFTEST-BLOCK"), 200, 2);
                var first = BuildUdp("203.0.113.41", 27015, "192.0.2.1", 50000, pair[0]);
                Check(!NameLayer.DecidePacket(first, first.Length), "T12 reload 前缓存首片");
                NameLayer.LoadRules();
                last = BuildUdp("203.0.113.41", 27015, "192.0.2.1", 50000, pair[1]);
                Check(!NameLayer.DecidePacket(last, last.Length), "T12 LoadRules 清掉旧分片缓存");
                ClearTestBlocked();
                var harmless = SplitReply(A2sReply("SAFE-SERVER"), 201, 2);
                foreach (var part in harmless)
                {
                    var p = BuildUdp("203.0.113.42", 27015, "192.0.2.1", 50000, part);
                    Check(!NameLayer.DecidePacket(p, p.Length), "T12 无害完整分片响应放行");
                }
            }
            finally { ClearTestBlocked(); NameLayer.NameOnlyMode = oldMode; }
        }

        // ---------------------------------------------------------------- 13
        private static void T13_EndpointReconcile(Action<string> log)
        {
            // 只使用 Run 已切换的临时 Root，不调用扫描/启动拦截。
            IpEngine.WritePendingRaw(new List<IpEngine.PendingItem>());
            IpEngine.WriteEntries(new List<IpEntry>
            {
                new IpEntry { Address = "203.0.113.50:027015", Note = "keep" },
                new IpEntry { Address = "203.0.113.50:27015", Note = "duplicate" },
                new IpEntry { Address = "203.0.113.50:27016" },
                new IpEntry { Address = "203.0.113.50" },
                new IpEntry { Address = "203.0.113.50!27017" },
                new IpEntry { Address = "203.0.113.51:0" },
                new IpEntry { Address = "203.0.113.51/24:27015" }
            });
            Reconcile();
            var clean = IpEngine.ReadEntries();
            Check(clean.Count == 3 && clean.Any(x => x.Address == "203.0.113.50:27015" && x.Note == "keep") && clean.Any(x => x.Address == "203.0.113.50:27016") && clean.Any(x => x.Address == "203.0.113.50"), "T13 Reconcile 规范化去重并保留不同端口/裸 IP");
            var before = File.ReadAllBytes(IpEngine.IpFile);
            Reconcile();
            Check(before.SequenceEqual(File.ReadAllBytes(IpEngine.IpFile)), "T13 Reconcile 第二次运行 IP 清单幂等");
            IpEngine.InvalidateRangeCache();
        }

        // ---------------------------------------------------------------- 24
        private static void T24_SharedNameIpRepair(Action<string> log)
        {
            // 旧版本把"无限火力"解析成裸 IP 45.125.45.95，同 IP 上几千个黑喵端口被连坐。
            // 这里用 TEST-NET 地址复现：同一 IP 两个服名 → 只保留被解析名字的端口。
            IpEngine.WriteEntries(new List<IpEntry>
            {
                new IpEntry { Address = "203.0.113.60", Note = "BAD（按名字解析）" },
                new IpEntry { Address = "203.0.113.61", Note = "DEDICATED（按名字解析）" }
            });
            IpEngine.WriteLinks(new List<IpEngine.IpLink>
            {
                new IpEngine.IpLink { Rule = "BAD", Ip = "203.0.113.60", Name = "BAD", Time = "2026-11-14 00:00:00", Source = "custom", Introduced = true }
            });
            File.WriteAllText(IpEngine.NameMapFile,
                "BAD\t203.0.113.60:27015\r\nGOOD\t203.0.113.60:27016\r\nDEDICATED\t203.0.113.61:27015\r\n",
                new UTF8Encoding(false));

            int repaired = IpEngine.RepairSharedNameBlocks(null);
            var entries = IpEngine.ReadEntries();
            var links = IpEngine.ReadLinks();
            Check(repaired == 1, "T24 修复共享 IP 裸条目", "repaired=" + repaired);
            Check(!entries.Any(e => e.Address == "203.0.113.60"), "T24 共享 IP 的裸条目已移除");
            Check(entries.Any(e => e.Address == "203.0.113.60:27015"), "T24 改为被解析名字的精确端口");
            Check(!entries.Any(e => e.Address == "203.0.113.60:27016"), "T24 不连坐同 IP 的其它端口");
            Check(entries.Any(e => e.Address == "203.0.113.61"), "T24 独占 IP 仍保留裸 IP");
            Check(links.Any(l => l.Rule == "BAD" && l.Ip == "203.0.113.60:27015" && l.Introduced),
                  "T24 名字规则关联迁移到精确端口");
            Check(!links.Any(l => l.Ip == "203.0.113.60"), "T24 旧裸 IP 关联已移除");

            NameLayer.ReloadIpBlocked();
            Check(NameLayer.IpEndpointBlockedForTest("203.0.113.60", 27015), "T24 名字层执行 ip_block 精确 endpoint");
            Check(!NameLayer.IpEndpointBlockedForTest("203.0.113.60", 27016), "T24 名字层不扩大 endpoint 范围");

            var beforeIp = File.ReadAllBytes(IpEngine.IpFile);
            var beforeLinks = File.ReadAllBytes(IpEngine.LinkFile);
            Check(IpEngine.RepairSharedNameBlocks(null) == 0 &&
                  beforeIp.SequenceEqual(File.ReadAllBytes(IpEngine.IpFile)) &&
                  beforeLinks.SequenceEqual(File.ReadAllBytes(IpEngine.LinkFile)),
                  "T24 修复幂等");

            // 新解析：共享 IP 直接写精确端口；独占 IP 仍写裸 IP。
            File.WriteAllText(IpEngine.NameMapFile,
                "NEWBAD\t203.0.113.62:27015\r\nOTHER\t203.0.113.62:27016\r\nDEDICATED2\t203.0.113.63:27015\r\n",
                new UTF8Encoding(false));
            IpEngine.WriteEntries(new List<IpEntry>());
            List<string> matched;
            var addedShared = IpEngine.AddNameToBlockList("NEWBAD", out matched);
            Check(addedShared.Count == 1 && addedShared[0] == "203.0.113.62:27015",
                  "T24 新加共享 IP 服名只加精确端口", string.Join(",", addedShared.ToArray()));
            Check(entries.All(e => e.Address != "203.0.113.62") &&
                  IpEngine.ReadEntries().All(e => e.Address != "203.0.113.62"),
                  "T24 新加共享 IP 服名不写裸 IP");
            var addedDedicated = IpEngine.AddNameToBlockList("DEDICATED2", out matched);
            Check(addedDedicated.Count == 1 && addedDedicated[0] == "203.0.113.63",
                  "T24 新加独占 IP 服名仍写裸 IP", string.Join(",", addedDedicated.ToArray()));

            // 清掉本测试的清单，避免影响后续用例。
            IpEngine.WriteEntries(new List<IpEntry>());
            NameLayer.ReloadIpBlocked();
        }

        private static void T14_CapLocate(Action<string> log)
        {
            var hits = CapLocate.AggregateHits(new[] {
                new A2sHit { Name = "actual", Ip = "203.0.113.70", Port = 27015 },
                new A2sHit { Name = "actual", Ip = "203.0.113.70", Port = 27015 },
                new A2sHit { Name = "different", Ip = "203.0.113.70", Port = 27015 },
                new A2sHit { Name = "actual", Ip = "203.0.113.70", Port = 27016 },
                new A2sHit { Name = "invalid", Ip = "127.1", Port = 27015 },
                new A2sHit { Name = "invalid", Ip = "203.0.113.70", Port = 0 }
            });
            Check(hits.Count == 3 && hits.Any(h => h.Endpoint == "203.0.113.70:27015" && h.Name == "actual" && h.Count == 2), "T14 候选按真实名称+endpoint聚合次数");
            Check(hits.All(h => h.Source == "A2S应答"), "T14 候选来源明确");
            bool cancelled = false;
            try { CapLocate.Capture(30, null, new System.Threading.CancellationToken(true)); } catch (OperationCanceledException) { cancelled = true; }
            Check(cancelled, "T14 已取消令牌不启动pktmon");
        }

        private static void T15_GroupListDiagnostics(Action<string> log)
        {
            var client = GroupListDiagnostics.DetectMarkers(
                "GroupServer SteamMatchGameSearch001 JoinSteamGroup m_iServerSteamGroupID", GroupListDiagnostics.ClientMarkers);
            Check(client.Count == GroupListDiagnostics.ClientMarkers.Length &&
                  client.Contains("GroupServer") && client.Contains("SteamMatchGameSearch001"),
                  "T15 组服客户端标记识别");

            var browser = GroupListDiagnostics.DetectMarkers(
                "SteamMatchMakingServers002 CServerBrowserDialog ServerBrowser.vdf", GroupListDiagnostics.BrowserMarkers);
            Check(browser.Count == GroupListDiagnostics.BrowserMarkers.Length && browser.Contains("CServerBrowserDialog"),
                  "T15 通用浏览器标记识别");
            Check(GroupListDiagnostics.DetectMarkers("A2S_INFO only", GroupListDiagnostics.ClientMarkers).Count == 0,
                  "T15 A2S 文本不能冒充组服客户端标记");
        }

        private static void T16_GroupFilter(Action<string> log)
        {
            // 规则只有一份统一文件 rules-profiles\custom.txt：先放 .unified 标记，
            // 避免 EnsureAssets 触发迁移把测试用的规则文件覆盖掉（这里整棵树都在临时 Root 下）。
            Directory.CreateDirectory(SteamServerFilterRules.Engine.ProfileDir);
            SafeFile.Write(SteamServerFilterRules.Engine.UnifiedMarker, "unified selftest\r\n");

            // 1) 中文规则 → 纯 ASCII 的 \xHH 转义（DLL 用 CP_ACP 读 ini，不能直接放 UTF-8 中文）
            Check(GroupServerFilter.AsciiEscape("PURE L4D2") == "PURE L4D2", "T16 纯 ASCII 规则原样保留");
            Check(GroupServerFilter.AsciiEscape("纯娱乐") == @"\xE7\xBA\xAF\xE5\xA8\xB1\xE4\xB9\x90",
                  "T16 中文规则转 UTF-8 字节转义");

            // ini 里的 \xHH 是给原生 std::regex 按【字节】匹配的；.NET 这边把 UTF-8 字节映射成 char 再验语义
            Func<string, string> byteView = s =>
            {
                var bs = Encoding.UTF8.GetBytes(s);
                var cs = new char[bs.Length];
                for (int i = 0; i < bs.Length; i++) cs[i] = (char)bs[i];
                return new string(cs);
            };

            string regex = "", err = "";
            var savedCustom = File.Exists(SteamServerFilterRules.Engine.CustomFile) ? SafeFile.Read(SteamServerFilterRules.Engine.CustomFile) : null;
            try
            {
                // 2) 统一规则文件 → 整串匹配正则（默认四条就是现在实机在用的规则；统一文件里不写 ^$，转成子串分支）
                SafeFile.Write(SteamServerFilterRules.Engine.CustomFile,
                    "# 默认规则（统一文件：名字层丢包 + 组服列表删行共用）\r\n" +
                    "[Pp][Ll][Uu][Ss] L4D2 [0-9][0-9] #[0-9]+\r\n" +
                    "[Pp][Uu][Rr][Ee] L4D2 .*\r\n" +
                    "纯天然多特战役服\r\n" +
                    "纯娱乐\r\n");
                int nlTotal, nlMerged, nlSkipped;
                List<string> nlSkips;
                Check(GroupServerFilter.BuildRegexEx(out regex, out err, out nlTotal, out nlMerged, out nlSkipped, out nlSkips) &&
                      nlTotal == 4 && nlMerged == 4 && nlSkipped == 0,
                      "T16 统一规则全部并入组服正则", err);
                Check(regex.StartsWith("^(") && regex.EndsWith(")$"), "T16 正则整串匹配");
                var re = new Regex(regex);
                Check(re.IsMatch(byteView("PLUS L4D2 21 #7")), "T16 默认规则删 PLUS 行");
                Check(re.IsMatch(byteView("PURE L4D2 02 #5")), "T16 默认规则删 PURE 行");
                Check(re.IsMatch(byteView("纯天然多特战役服-回归本真")), "T16 默认规则删纯天然行");
                Check(re.IsMatch(byteView("纯娱乐多特战役服-喷子天下")), "T16 默认规则删纯娱乐行");
                Check(!re.IsMatch(byteView("51.高级多特")) && !re.IsMatch(byteView("Left 4 Dead 2")) && !re.IsMatch(byteView("pure l4d2 01 #1")),
                      "T16 默认规则不误删其他服");

                // 3) 名字层写法直接写进同一个文件就能生效：裸名字 / (?i) / 中文都行
                string why;
                Check(GroupServerFilter.NameLayerRuleToGroupFragment("神之右手", out why) == ".*(?:神之右手).*",
                      "T16 名字层中文规则包成子串分支");
                var nlFrag = GroupServerFilter.NameLayerRuleToGroupFragment("(?i)plus[ -]*l4d2", out why);
                Check(nlFrag != null && nlFrag.StartsWith(".*(?:") && !nlFrag.Contains("(?i)") && nlFrag.Contains("[Pp][Ll][Uu][Ss]"),
                      "T16 名字层 (?i) 展开成 ASCII 大小写字符类");
                Check(GroupServerFilter.NameLayerRuleToGroupFragment("(?<=x)y", out why) == null,
                      "T16 名字层 lookbehind 会被跳过");
                Check(GroupServerFilter.NameLayerRuleToGroupFragment("(?=x)y", out why) == null,
                      "T16 名字层 lookahead 会被跳过");
                Check(GroupServerFilter.NameLayerRuleToGroupFragment("(a)\\1", out why) == null,
                      "T16 名字层反向引用会被跳过");

                SafeFile.Write(SteamServerFilterRules.Engine.CustomFile, "神之右手\r\n(?i)pure[ -]*l4d2\r\n[Rr][Pp][Gg]\r\n");
                Check(GroupServerFilter.BuildRegexEx(out regex, out err, out nlTotal, out nlMerged, out nlSkipped, out nlSkips) &&
                      nlTotal == 3 && nlMerged == 3 && nlSkipped == 0,
                      "T16 名字层写法在统一文件里直接生效", err);
                var reNl = new Regex(regex);
                Check(reNl.IsMatch(byteView("x神之右手服")) && reNl.IsMatch(byteView("PURE L4D2 02 #5")) && reNl.IsMatch(byteView("RPG-L4D2")),
                      "T16 名字层规则在组服正则里真的命中");
                Check(!reNl.IsMatch(byteView("51.高级多特")) && !reNl.IsMatch(byteView("CORE-SS :: SG Coop")),
                      "T16 名字层规则不误删其他服");

                // 不支持的写法只跳过这一条（其它规则照常生效），并记录原因
                SafeFile.Write(SteamServerFilterRules.Engine.CustomFile, "神之右手\r\n(?<=x)y\r\n");
                Check(GroupServerFilter.BuildRegexEx(out regex, out err, out nlTotal, out nlMerged, out nlSkipped, out nlSkips) &&
                      nlTotal == 2 && nlMerged == 1 && nlSkipped == 1 && nlSkips.Count == 1,
                      "T16 不兼容的规则被跳过并记录原因", err);

                // 「仅名字层」标记段：段内规则名字层照常用，但不进组服列表删行正则
                SafeFile.Write(SteamServerFilterRules.Engine.CustomFile,
                    "神之右手\r\n" +
                    SteamServerFilterRules.Engine.NameOnlyStart + "\r\n" +
                    "保留这一行的服\r\n" +
                    SteamServerFilterRules.Engine.NameOnlyEnd + "\r\n");
                Check(GroupServerFilter.BuildRegexEx(out regex, out err, out nlTotal, out nlMerged, out nlSkipped, out nlSkips) &&
                      nlTotal == 2 && nlMerged == 1 && nlSkipped == 1 &&
                      nlSkips.Count == 1 && nlSkips[0].Contains("仅名字层"),
                      "T16 仅名字层的规则不参与组服删行", err);
                var reScope = new Regex(regex);
                Check(reScope.IsMatch(byteView("x神之右手服")) && !reScope.IsMatch(byteView("保留这一行的服")),
                      "T16 仅名字层规则不进组服正则");
                Check(SteamServerFilterRules.Engine.ReadProfileRules("custom").Contains("保留这一行的服"),
                      "T16 仅名字层规则仍在名字层生效");

                // 失败关闭：条目超过上限时整层拒绝生成（不做半套过滤）
                var many = new StringBuilder();
                for (int i = 0; i <= GroupServerFilter.MaxRuleFragments; i++) many.Append("rule").Append(i).Append("\r\n");
                SafeFile.Write(SteamServerFilterRules.Engine.CustomFile, many.ToString());
                Check(!GroupServerFilter.BuildRegex(out regex, out err) && err.Contains("超过上限"),
                      "T16 规则条数超过上限时 fail-closed", err);
            }
            finally
            {
                if (savedCustom == null) { try { File.Delete(SteamServerFilterRules.Engine.CustomFile); } catch { } }
                else SafeFile.Write(SteamServerFilterRules.Engine.CustomFile, savedCustom);
            }

            // 4) 安全匹配引擎（与钩子同一套实现）：灾难性正则无回溯，危险构造/超长直接拒绝
            string nerr;
            Check(GroupServerFilter.NativeValidateRegex("^(?:a+)+$", out nerr),
                  "T16 安全引擎接受嵌套量词语法", nerr);
            var evil = new string('a', 140) + "!";
            Check(GroupServerFilter.NativeTestMatch("^(?:a+)+$", evil, out nerr) == 0,
                  "T16 灾难性正则有界返回不匹配", nerr);
            Check(!GroupServerFilter.NativeValidateRegex("(?=x)y", out nerr),
                  "T16 安全引擎拒绝 lookahead");
            Check(!GroupServerFilter.NativeValidateRegex(new string('a', 2049), out nerr),
                  "T16 安全引擎拒绝超长正则");
            const string plusPattern = "^(?:[Pp][Ll][Uu][Ss] L4D2 [0-9][0-9] #[0-9]+)$";
            Check(GroupServerFilter.NativeTestMatch(plusPattern, "PLUS L4D2 01 #3", out nerr) == 1,
                  "T16 安全引擎匹配 PLUS 行", nerr);
            Check(GroupServerFilter.NativeTestMatch(plusPattern, "PLUS L4D2 1 #3", out nerr) == 0,
                  "T16 安全引擎不匹配单数字编号", nerr);

            // 5) 空规则 = 不过滤；ini 里 filter=1 才真删行
            SafeFile.Write(SteamServerFilterRules.Engine.CustomFile, "# 只有注释\r\n\r\n");
            Check(GroupServerFilter.BuildRegex(out regex, out err) && regex.Length == 0,
                  "T16 空规则不拦任何行", err);
            var ini = GroupServerFilter.BuildIniText(true, "^(A|B)$");
            Check(ini.Contains("filter=1") && ini.Contains("regex=^(A|B)$") &&
                  ini.Contains("dedupe_names=1") &&
                  ini.Contains("expected_sha256=" + GroupServerFilter.ExpectedSha256),
                  "T16 ini 含过滤开关/正则/去重开关/指纹");

            // 6) 内嵌原生 DLL 能解包成 x86 PE 且导出 SSF_Start（自动注入靠它）
            Check(GroupServerFilter.EnsureAssets(out err), "T16 内嵌原生 DLL 能解包", err);
            var dllBytes = File.ReadAllBytes(GroupServerFilter.DllPath);
            var peOff = dllBytes.Length > 0x40 ? BitConverter.ToInt32(dllBytes, 0x3C) : 0;
            Check(dllBytes.Length > 1024 && dllBytes[0] == 0x4D && dllBytes[1] == 0x5A &&
                  peOff > 0 && peOff + 6 < dllBytes.Length && BitConverter.ToUInt16(dllBytes, peOff + 4) == 0x014C,
                  "T16 解包出的 DLL 是 x86 PE");
            int exportRva;
            Check(GroupServerFilter.TryGetExportRva(GroupServerFilter.DllPath, "SSF_Start", out exportRva, out err) &&
                  exportRva > 0, "T16 DLL 导出 SSF_Start", err);

            // 7) 原生重复名称表：首次 0、再次 1、大小写/前后缀不同不算重复、空名字不去重、重置后重新计数
            string derr;
            Check(GroupServerFilter.NativeDedupeReset(out derr), "T16 原生去重表可重置", derr);
            Check(GroupServerFilter.NativeDedupeCheck("重复服", out derr) == 0, "T16 首次出现的名字保留", derr);
            Check(GroupServerFilter.NativeDedupeCheck("重复服", out derr) == 1, "T16 本轮再次出现同名判定为重复", derr);
            Check(GroupServerFilter.NativeDedupeCheck("另一个服", out derr) == 0, "T16 新名字不受已有名字影响", derr);
            Check(GroupServerFilter.NativeDedupeCheck("重复服2", out derr) == 0, "T16 前缀相同但名字不同不算重复", derr);
            Check(GroupServerFilter.NativeDedupeCheck("RP", out derr) == 0, "T16 大小写不同算两个名字", derr);
            Check(GroupServerFilter.NativeDedupeCheck("rp", out derr) == 0, "T16 大小写不同算两个名字（小写）", derr);
            Check(GroupServerFilter.NativeDedupeCheck("", out derr) == 0, "T16 空名字不参与去重", derr);
            Check(GroupServerFilter.NativeDedupeCheck("", out derr) == 0, "T16 空名字第二次仍不跳过", derr);

            // 8) 末尾 #数字 后缀（截图中同一台服务器的 #90/#85/#73）按同一台处理；开头 BOM 也不影响
            Check(GroupServerFilter.NativeDedupeReset(out derr), "T16 去重表重置（后缀用例）", derr);
            Check(GroupServerFilter.NativeDedupeCheck("【黑喵3】多人多特 #90", out derr) == 0, "T16 带 #90 的名字首次保留", derr);
            Check(GroupServerFilter.NativeDedupeCheck("【黑喵3】多人多特 #85", out derr) == 1, "T16 #85 视为 #90 的同一台服务器", derr);
            Check(GroupServerFilter.NativeDedupeCheck("【黑喵3】多人多特 #73", out derr) == 1, "T16 #73 视为同一台服务器", derr);
            Check(GroupServerFilter.NativeDedupeCheck("【黑喵3】多人多特 # 85", out derr) == 1, "T16 # 与数字间有空格也视为后缀", derr);
            Check(GroupServerFilter.NativeDedupeCheck("【黑喵3】多人多特", out derr) == 1, "T16 不带后缀的名字仍视为同一台", derr);
            Check(GroupServerFilter.NativeDedupeCheck("【黑喵3】多人多特 #A", out derr) == 0, "T16 # 后不是数字不按后缀处理", derr);
            Check(GroupServerFilter.NativeDedupeCheck("\uFEFF【黑喵3】多人多特 #90", out derr) == 1, "T16 开头 BOM 不影响去重", derr);
            Check(GroupServerFilter.NativeDedupeCheck("Server 1", out derr) == 0, "T16 没有 # 的编号仍是不同名字（1）", derr);
            Check(GroupServerFilter.NativeDedupeCheck("Server 2", out derr) == 0, "T16 没有 # 的编号仍是不同名字（2）", derr);
            Check(GroupServerFilter.NativeDedupeReset(out derr), "T16 去重表重置（纯编号用例）", derr);
            Check(GroupServerFilter.NativeDedupeCheck("#95", out derr) == 0, "T16 只有编号的名字不被当成空名字（95）", derr);
            Check(GroupServerFilter.NativeDedupeCheck("#96", out derr) == 0, "T16 只有编号的名字不被当成空名字（96）", derr);
            Check(GroupServerFilter.NativeDedupeReset(out derr), "T16 原生去重表再次重置", derr);
            Check(GroupServerFilter.NativeDedupeCheck("重复服", out derr) == 0, "T16 重置后同一名字重新保留", derr);

            // 9) 游戏会在同一轮刷新中重复构建列表（相同的前两个名字再次出现），
            //    第二次构建前会清空列表；检测到该前缀时必须清空去重表，否则整页会被跳过。
            Check(GroupServerFilter.NativeDedupeReset(out derr), "T16 去重表重置（重复构建用例）", derr);
            Check(GroupServerFilter.NativeDedupeCheck("P1", out derr) == 0, "T16 第一遍 P1 保留", derr);
            Check(GroupServerFilter.NativeDedupeCheck("P2", out derr) == 0, "T16 第一遍 P2 保留", derr);
            Check(GroupServerFilter.NativeDedupeCheck("P3", out derr) == 0, "T16 第一遍 P3 保留", derr);
            Check(GroupServerFilter.NativeDedupeCheck("P1", out derr) == 1, "T16 第一遍 P1 再次出现跳过", derr);
            Check(GroupServerFilter.NativeDedupeCheck("P2", out derr) == 0, "T16 检测到 P1,P2 前缀后开始新一遍（P2 保留）", derr);
            Check(GroupServerFilter.NativeDedupeCheck("P1", out derr) == 0, "T16 新一遍 P1 保留", derr);
            Check(GroupServerFilter.NativeDedupeCheck("P3", out derr) == 0, "T16 新一遍 P3 保留", derr);
            Check(GroupServerFilter.NativeDedupeCheck("P2", out derr) == 1, "T16 新一遍 P2 再次出现跳过", derr);
        }

        // T18：进程/计划任务生命周期必须统一指向 FilterTool 常驻拦截，
        //      旧引擎 SteamServerFilter.exe 已归档，任何入口都不得再把用户引回旧 exe。
        private static void T18_Lifecycle(Action<string> log)
        {
            Check(SteamServerFilterRules.Engine.TaskName == IpEngine.TaskName,
                "T18 规则侧任务名与常驻拦截一致",
                SteamServerFilterRules.Engine.TaskName + " vs " + IpEngine.TaskName);
            Check(string.Equals(SteamServerFilterRules.Engine.FilterExeName, "FilterTool.exe", StringComparison.OrdinalIgnoreCase),
                "T18 生命周期入口是 FilterTool.exe",
                SteamServerFilterRules.Engine.FilterExeName);
            Check(!string.Equals(SteamServerFilterRules.Engine.FilterExeName, "SteamServerFilter.exe", StringComparison.OrdinalIgnoreCase),
                "T18 生命周期不再指向旧引擎");
            Check(SteamServerFilterRules.Engine.TaskName == "SteamServerFilter IP Block",
                "T18 任务名是 SteamServerFilter IP Block",
                SteamServerFilterRules.Engine.TaskName);
        }

        // T19：P1 安全预算与原子性回归（token、名字层预算、畸形 pcapng、并发写入、镜像路径识别）
        private static bool NoThrow(Action body)
        {
            try { body(); return true; } catch { return false; }
        }

        private static void T19_SecurityBudget(Action<string> log)
        {
            // 1) 组服会话 token：32 位十六进制、可持久化、轮换后变化、能写进 ini
            string terr;
            var t1 = GroupServerFilter.EnsureSessionToken(out terr);
            Check(t1.Length == 32 && t1.All(c => (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')),
                  "T19 会话 token 为 32 位小写十六进制", terr);
            Check(string.Equals(GroupServerFilter.SessionToken, t1, StringComparison.Ordinal),
                  "T19 token 写入 config.ini 后能读回");
            var t2 = GroupServerFilter.RotateSessionToken(out terr);
            Check(t2.Length == 32 && !string.Equals(t1, t2, StringComparison.OrdinalIgnoreCase),
                  "T19 轮换会话 token 后旧值失效");
            var ini = GroupServerFilter.BuildIniText(true, "x", t2);
            Check(ini.Contains("session_token=" + t2), "T19 ini 文本携带会话 token");
            Check(GroupServerFilter.BuildIniText(false, "").Contains("session_token="),
                  "T19 二参 ini 生成也会带上 token 字段");

            // 2) 名字层规则预算：最多 200 条 / 20000 字符，超出部分丢弃并记录原因
            var rulesPath = SteamServerFilterRules.Engine.RulesFile;
            long droppedBefore = NameLayer.RuleLimitDropped;
            var many = new StringBuilder();
            for (int i = 0; i < 250; i++) many.Append("BUDGET" + i.ToString("000") + "\r\n");
            SafeFile.Write(rulesPath, many.ToString());
            NameLayer.LoadRules();
            Check(NameLayer.RuleLimitDropped - droppedBefore == 50, "T19 名字层超过 200 条时精确丢弃 50 条",
                  "dropped=" + (NameLayer.RuleLimitDropped - droppedBefore));
            Check(NameLayer.LastError.Contains("超过预算"), "T19 名字层超预算给出可读原因", NameLayer.LastError);
            Check(NameLayer.MatchRule("BUDGET000") != null, "T19 预算内的规则仍然生效");
            Check(NameLayer.MatchRule("BUDGET249") == null, "T19 超出预算的规则不生效");

            long dropped2 = NameLayer.RuleLimitDropped;
            SafeFile.Write(rulesPath, new string('a', 11000) + "\r\n" + new string('b', 11000) + "\r\n");
            NameLayer.LoadRules();
            Check(NameLayer.RuleLimitDropped - dropped2 == 1, "T19 规则总字符超 20000 时丢弃后续规则",
                  "dropped=" + (NameLayer.RuleLimitDropped - dropped2));

            // 3) 畸形 pcapng：块长度伪造/截断/垃圾文件只能返回空结果，不能抛异常或越界
            var shb = new byte[] {
                0x0A, 0x0D, 0x0D, 0x0A, 0x1C, 0x00, 0x00, 0x00, 0x4D, 0x3C, 0x2B, 0x1A,
                0x01, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x1C, 0x00, 0x00, 0x00 };
            var badOk = Path.Combine(IpEngine.Root, "pcap-ok-empty.pcapng");
            var badTotal = Path.Combine(IpEngine.Root, "pcap-bad-total.pcapng");
            var badGarbage = Path.Combine(IpEngine.Root, "pcap-garbage.pcapng");
            File.WriteAllBytes(badOk, shb);
            var badTotalBytes = new byte[shb.Length + 16];
            Array.Copy(shb, badTotalBytes, shb.Length);
            File.WriteAllBytes(badTotal, badTotalBytes);
            File.WriteAllBytes(badGarbage, Encoding.ASCII.GetBytes(new string('X', 64)));
            Check(NoThrow(() => { CapLocate.TopPeers(badOk); }), "T19 只有 SHB 的 pcapng 不抛异常");
            Check(NoThrow(() => { CapLocate.TopPeers(badTotal); }), "T19 伪造超大块长度不抛异常");
            Check(NoThrow(() => { CapLocate.ParseFile(badTotal, log); }), "T19 畸形块不会越界读取");
            Check(CapLocate.TopPeers(badOk).Count == 0 && CapLocate.ParseFile(badGarbage, log).Count == 0,
                  "T19 畸形 pcapng 返回空结果");

            // 4) 并发原子写：多线程写同一状态文件后内容必须是某一次完整写入，且没有残留 .tmp
            var atomic = Path.Combine(IpEngine.Root, "atomic-state.txt");
            int writeErrors = 0;
            var threads = new List<System.Threading.Thread>();
            for (int w = 0; w < 8; w++)
            {
                int id = w;
                var th = new System.Threading.Thread(() =>
                {
                    try
                    {
                        for (int k = 0; k < 100; k++) SafeFile.Write(atomic, "writer=" + id + ";" + new string((char)('A' + id), 200));
                    }
                    catch { System.Threading.Interlocked.Increment(ref writeErrors); }
                });
                th.IsBackground = true;
                threads.Add(th);
            }
            foreach (var th in threads) th.Start();
            foreach (var th in threads) th.Join(60000);
            string fin = File.Exists(atomic) ? File.ReadAllText(atomic) : "";
            var m = Regex.Match(fin, "^writer=([0-7]);(.)\\2{199}$");
            Check(writeErrors == 0, "T19 并发原子写不抛异常", "errors=" + writeErrors);
            Check(m.Success && (char)('A' + int.Parse(m.Groups[1].Value)) == m.Groups[2].Value[0],
                  "T19 并发写入后文件是某一次完整写入（不撕裂）", "len=" + fin.Length + " head=" + (fin.Length > 40 ? fin.Substring(0, 40) : fin));
            var leftovers = Directory.GetFiles(IpEngine.Root, "atomic-state.txt.tmp*");
            Check(leftovers.Length == 0, "T19 原子写不残留临时文件", string.Join(",", leftovers));

            // 5) 生命周期只认可安装目录里的 FilterTool.exe 镜像，同名不同路径不算自己人
            var self = System.Diagnostics.Process.GetCurrentProcess();
            string selfPath = "";
            try { selfPath = self.MainModule.FileName; } catch { }
            Check(selfPath.Length > 0 && Lifecycle.MatchesImage(self, new[] { selfPath }),
                  "T19 生命周期按镜像全路径识别自身");
            Check(!Lifecycle.MatchesImage(self, new[] { Path.Combine(IpEngine.Root, "FilterTool.exe") }),
                  "T19 生命周期不把同名不同路径的进程当自己人");
        }

        private static void T20_ConfigSingleSource(Action<string> log)
        {
            // P2-2：config.ini 是主事实源；旧单值文件（含 .active-profile）只在缺键时回退。
            var cfg = Config.File;
            var state = SteamServerFilterRules.Engine.StateFile;
            var profileDir = SteamServerFilterRules.Engine.ProfileDir;
            Action<string> del = p => { try { if (File.Exists(p)) File.Delete(p); } catch { } };
            del(cfg); del(state);
            // T16/T23 会写统一标记；这里删掉，才能测「规则统一前」的旧回退路径。
            del(SteamServerFilterRules.Engine.UnifiedMarker);
            Directory.CreateDirectory(profileDir);

            // 1) 只有旧文件时仍可读（兼容回退）
            SteamServerFilterIpBlock.SafeFile.Write(state, "cn");
            Check(SteamServerFilterRules.Engine.GetActiveProfile() == "cn",
                  "T20 无 config.ini 时回退到 .active-profile", SteamServerFilterRules.Engine.GetActiveProfile());

            // 2) SetActiveProfile 双写：config.ini 主事实源 + 旧文件兼容
            SteamServerFilterRules.Engine.SetActiveProfile("rpg+custom");
            Check(Config.Get("active-profile") == "rpg+custom",
                  "T20 active-profile 写入 config.ini", Config.Get("active-profile") ?? "(null)");
            Check(File.ReadAllText(state).Trim() == "rpg+custom",
                  "T20 旧 .active-profile 仍双写兼容", File.ReadAllText(state).Trim());

            // 3) config.ini 优先：只改旧文件不生效
            SteamServerFilterIpBlock.SafeFile.Write(state, "pureplus");
            Check(SteamServerFilterRules.Engine.GetActiveProfile() == "rpg+custom",
                  "T20 config.ini 优先于旧 .active-profile", SteamServerFilterRules.Engine.GetActiveProfile());

            // 4) Migrate 在 config.ini 缺键时把旧值迁入
            del(cfg);
            SteamServerFilterIpBlock.SafeFile.Write(state, "cn");
            Config.Migrate();
            Check(Config.Get("active-profile") == "cn",
                  "T20 --config-migrate 迁入 .active-profile", Config.Get("active-profile") ?? "(null)");

            // 5) 审计必须标出冲突，且绝不输出会话 token 明文
            Config.Set("name-layer", "off");
            SteamServerFilterIpBlock.SafeFile.Write(NameLayer.FlagFile, "on");
            var fakeToken = new string('a', 32);
            Config.Set(GroupServerFilter.ConfigKeyToken, fakeToken);
            var audit = Config.Audit();
            Check(audit.Any(l => l.Contains("冲突")), "T20 审计报告 config.ini 与旧文件冲突");
            Check(audit.All(l => l.IndexOf(fakeToken, StringComparison.Ordinal) < 0),
                  "T20 审计不输出会话 token 明文");
        }

        private static void T21_RuleService(Action<string> log)
        {
            // P2-1：规则校验/添加/生成/备份/恢复只有一份实现（Engine），CLI / PowerShell / GUI 共用。
            var rules = SteamServerFilterRules.Engine.RulesFile;
            var profileDir = SteamServerFilterRules.Engine.ProfileDir;
            var custom = SteamServerFilterRules.Engine.CustomFile;
            var backupDir = SteamServerFilterRules.Engine.BackupDir;
            var cfg = Config.File;
            Action<string> del = p => { try { if (File.Exists(p)) File.Delete(p); } catch { } };
            del(cfg); del(rules); del(custom);
            try { if (Directory.Exists(backupDir)) Directory.Delete(backupDir, true); } catch { }
            Directory.CreateDirectory(profileDir);

            // 1) 生成：档位文件 → block_rules.txt
            SteamServerFilterIpBlock.SafeFile.Write(Path.Combine(profileDir, "rpg.txt"), "[Rr][Pp][Gg]\r\n");
            SteamServerFilterIpBlock.SafeFile.Write(Path.Combine(profileDir, "custom.txt"), "# custom\r\n");
            var rc = SteamServerFilterRules.Engine.ApplyProfile("rpg", false);
            Check(rc == 0 && File.Exists(rules), "T21 --rules-apply 生成 block_rules.txt", "rc=" + rc);

            // 2) 校验：正常文件通过
            var ok = SteamServerFilterRules.Engine.ValidateRulesFile();
            Check(ok.Ok && ok.RuleCount == 1 && ok.InSync, "T21 合法规则校验通过",
                  "issues=" + ok.Issues.Count + " rules=" + ok.RuleCount + " sync=" + ok.InSync);

            // 3) 校验能识别非法正则 / 乱码死规则 / 重复行 / 与档位不同步
            SteamServerFilterIpBlock.SafeFile.Write(rules, "[Rr][Pp][Gg]\r\n[unclosed\r\nbad\uFFFD\r\n[Rr][Pp][Gg]\r\n");
            var bad = SteamServerFilterRules.Engine.ValidateRulesFile();
            Check(bad.InvalidRegexCount >= 1, "T21 校验识别非法正则", "invalid=" + bad.InvalidRegexCount);
            Check(bad.MangledCount >= 1, "T21 校验识别乱码死规则", "mangled=" + bad.MangledCount);
            Check(bad.DuplicateCount >= 1, "T21 校验识别重复行", "dup=" + bad.DuplicateCount);
            Check(!bad.InSync, "T21 校验识别与规则文件不同步");

            // 4) 添加：已会被拦截的名字不重复写 custom
            var beforeCustom = File.ReadAllText(custom);
            var rcCovered = SteamServerFilterRules.Engine.AddCustomRule("某 RPG 服", false, false, false);
            Check(rcCovered == 0 && File.ReadAllText(custom) == beforeCustom,
                  "T21 已被现有规则覆盖的名字不重复添加", "rc=" + rcCovered);

            // 5) 添加新名字：写 custom、重建规则、并自动把 custom 并入启用组合
            var rcAdded = SteamServerFilterRules.Engine.AddCustomRule("唯一服名ABC", false, false, false);
            var customTxt = File.ReadAllText(custom);
            var afterAdd = SteamServerFilterRules.Engine.ValidateRulesFile();
            Check(rcAdded == 0 && customTxt.Contains("唯一服名ABC"), "T21 新名字写入 custom 档", "rc=" + rcAdded);
            Check(afterAdd.RuleCount == 2 && afterAdd.InSync,
                  "T21 添加后重建 2 条规则且与规则文件同步", "rules=" + afterAdd.RuleCount + " sync=" + afterAdd.InSync);
            Check(SteamServerFilterRules.Engine.GetActiveProfile().Split('+').Contains("custom"),
                  "T21 添加自定义规则后自动启用 custom 档", SteamServerFilterRules.Engine.GetActiveProfile());

            // 6) 备份：--rules-backup 写到 rules-profiles\\.backup\\
            var beforeBak = new HashSet<string>(Directory.Exists(backupDir) ? Directory.GetFiles(backupDir, "block_rules.txt.*.bak") : new string[0], StringComparer.OrdinalIgnoreCase);
            var rcBak = SteamServerFilterRules.Engine.BackupRules();
            var newBaks = Directory.Exists(backupDir)
                ? Directory.GetFiles(backupDir, "block_rules.txt.*.bak").Where(f => !beforeBak.Contains(f)).ToArray()
                : new string[0];
            Check(rcBak == 0 && newBaks.Length == 1 && File.Exists(newBaks[0]), "T21 --rules-backup 生成备份", "rc=" + rcBak);

            // 7) 恢复：--rules-restore 用备份覆盖当前文件
            var bakPath = newBaks.Length > 0 ? newBaks[0] : null;
            var bakText = bakPath != null ? File.ReadAllText(bakPath) : "";
            SteamServerFilterIpBlock.SafeFile.Write(rules, "XXX 临时内容\r\n");
            var rcRestore = bakPath != null ? SteamServerFilterRules.Engine.RestoreRules(Path.GetFileName(bakPath), false) : -1;
            Check(rcRestore == 0 && File.ReadAllText(rules) == bakText, "T21 --rules-restore 从备份恢复", "rc=" + rcRestore);

            // 8) PrintValidation：正常文件返回 0，报告字段齐全
            var sw = new StringWriter();
            var oldOut = Console.Out;
            int rcVal;
            string report;
            try { Console.SetOut(sw); rcVal = SteamServerFilterRules.Engine.PrintValidation(); report = sw.ToString(); }
            finally { Console.SetOut(oldOut); }
            Check(rcVal == 0 && report.Contains("生效规则") && report.Contains("与规则同步") && report.Contains("OK"),
                  "T21 --rules-validate 打印报告且返回 0", "rc=" + rcVal);

            // 9) 边界：缺文件 / 空名字 / 非法正则
            del(rules);
            var missing = SteamServerFilterRules.Engine.ValidateRulesFile();
            Check(!missing.Exists && !missing.Ok, "T21 缺 block_rules.txt 时校验报错");
            Check(SteamServerFilterRules.Engine.AddCustomRule("", false, false, false) == 2, "T21 空名字被拒绝");
            Check(SteamServerFilterRules.Engine.AddCustomRule("[", false, true, false) == 2, "T21 非法正则被拒绝");

            // 收尾：清掉本次自检的临时文件（都在临时 Root 下）
            del(rules); del(custom); del(cfg);
        }
        private static void T17_WinDivertPin(Action<string> log)
        {
            // P0-2：WinDivert.dll 只从程序目录（或其 windivert 子目录）加载，且必须与发布 SHA-256 一致；
            // 不再回退用户可写的 %APPDATA%\WindivertDotnet，否则提权进程会被 DLL 劫持。
            var dir = IpEngine.Root;
            var fake = Path.Combine(dir, "WinDivert.dll");
            File.WriteAllBytes(fake, new byte[] { 0x4D, 0x5A, 1, 2, 3, 4, 5, 6, 7, 8 });
            var found = Blocker.FindDll();
            Check(found.Length == 0, "T17 哈希不符的 WinDivert.dll 被拒绝", found);
            Check(Blocker.DllCheckError.Contains("不匹配") || Blocker.DllCheckError.Contains("找不到"),
                  "T17 拒绝原因可读", Blocker.DllCheckError);
            try { File.Delete(fake); } catch { }

            var shipped = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "windivert", "WinDivert.dll");
            if (File.Exists(shipped))
            {
                var hash = Blocker.Sha256File(shipped);
                Check(string.Equals(hash, Blocker.ExpectedDllSha256, StringComparison.OrdinalIgnoreCase),
                      "T17 发布包内 WinDivert.dll 与固定哈希一致", hash);
            }
        }

        // ================================================================ 2.2
        /// <summary>
        /// 状态收敛（2.2）：从事实源幂等地重建全部派生物，返回"做了哪些修改"的报告。 
        /// 事实源 = rules-profiles\*.txt（规则）、ip_block.txt（IP 清单）、block_rules.txt（现行规则）。
        /// </summary>
        public static List<string> Reconcile()
        {
            var report = new List<string>();

            // 1) 档位 → block_rules.txt
            try
            {
                var active = SteamServerFilterRules.Engine.GetActiveProfile();
                var before = SteamServerFilterRules.Engine.ReadEngineRules();
                var cnt = SteamServerFilterRules.Engine.ApplyCombo(active);
                if (cnt < 0) report.Add("× block_rules.txt 未重建：档位里有非 UTF-8 文件（见 --doc-check 提示）");
                else
                {
                    var after = SteamServerFilterRules.Engine.ReadEngineRules();
                    if (!before.SequenceEqual(after)) report.Add("· block_rules.txt 已按档位 " + active + " 重建：" + cnt + " 条");
                }
            }
            catch (Exception ex) { report.Add("× 重建 block_rules.txt 失败：" + ex.Message); }

            var current = new HashSet<string>(SteamServerFilterRules.Engine.ReadEngineRules(), StringComparer.Ordinal);

            // 2) links → 删掉"规则已不存在"的关联
            try
            {
                var links = IpEngine.ReadLinks();
                var dead = links.Where(l => l.Rule.Length > 0 && !current.Contains(l.Rule)).ToList();
                if (dead.Count > 0)
                {
                    IpEngine.WriteLinks(links.Where(l => !dead.Contains(l)).ToList());
                    report.Add("· 清理失效关联 " + dead.Count + " 条（规则已不存在）：" +
                               string.Join(", ", dead.Select(l => l.Rule + "→" + l.Ip).Take(5).ToArray()));
                }
            }
            catch (Exception ex) { report.Add("× 清理关联失败：" + ex.Message); }

            // 3) pending → 删掉"名字已被现有规则解释 且 IP 已在清单里"的条目
            try
            {
                var pend = IpEngine.ReadPending();
                var kept = new List<IpEngine.PendingItem>();
                int dropped = 0;
                foreach (var it in pend)
                {
                    var rule = NameLayer.MatchRuleWithRules(current.ToList(), it.Name);
                    var ips = IpEngine.ResolveIps(it.Name, out _, out _);
                    if (rule != null && ips.Count > 0 && ips.All(ip => IpEngine.ReadEntries().Any(e => IpEngine.SameBaseAddress(e.Address, ip))))
                    { dropped++; continue; }     // 名字已被规则覆盖、IP 也已在清单 → 无需再等
                    kept.Add(it);
                }
                if (dropped > 0)
                {
                    IpEngine.WritePendingRaw(kept);
                    report.Add("· 清理已完成的待解析条目 " + dropped + " 条（名字已被规则覆盖且 IP 已在清单）");
                }
            }
            catch (Exception ex) { report.Add("× 清理待解析失败：" + ex.Message); }

            // 4) name_layer_blocked.txt → 按现行规则重过滤
            try
            {
                int before = SafeFile.Read(NameLayer.BlockedFile).Replace("\r\n", "\n").Split('\n')
                    .Count(x => x.Trim().Length > 0 && !x.TrimStart().StartsWith("#"));
                if (before > 0)
                {
                    NameLayer.ReloadBlocked();     // 内部会丢掉"规则已不存在"的条目
                    int after = NameLayer.BlockedList().Count;
                    if (after != before)
                        report.Add("· 名字层封禁表已收敛：" + before + " → " + after + " 条");
                }
            }
            catch (Exception ex) { report.Add("× 收敛封禁表失败：" + ex.Message); }

            // 5) IP 清单 → 去掉重复/非法行
            try
            {
                var entries = IpEngine.ReadEntries();
                var seen = new HashSet<string>(StringComparer.Ordinal);
                var clean = new List<IpEntry>();
                int dup = 0, bad = 0;
                foreach (var e in entries)
                {
                    string ba; List<int> ex;
                    IpEngine.SplitExempt(e.Address, out ba, out ex);
                    if (!IpEngine.IsValidAddress(e.Address)) { bad++; continue; }
                    string ip; int port;
                    bool endpoint = IpEngine.TryParseEndpoint(e.Address, out ip, out port);
                    // 端口按整数规范化；裸 IP 与各端口身份分别保留。
                    string identity = endpoint ? ip + ":" + port : ba;
                    if (!seen.Add(identity)) { dup++; continue; }
                    if (endpoint) e.Address = identity;
                    clean.Add(e);
                }
                if (dup > 0 || bad > 0)
                {
                    IpEngine.WriteEntries(clean);
                    report.Add("· IP 清单已收敛：" + clean.Count + " 条（去重 " + dup + "，丢弃非法 " + bad + "）");
                }
            }
            catch (Exception ex) { report.Add("× 收敛 IP 清单失败：" + ex.Message); }

            if (report.Count == 0) report.Add("✓ 状态已一致，无需修改");
            return report;
        }
    }
}
