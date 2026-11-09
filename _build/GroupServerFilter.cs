// ============================================================================
//  GroupServerFilter —— 把「Steam 组战役模式服务器」列表行过滤（原生 SSF_GroupFilter2.dll）
//  合并进 FilterTool：
//    · 内嵌原生 DLL，首次使用时解包到 <Root>\groupfilter\
//    · 统一规则文件 rules-profiles\custom.txt（UTF-8，可写中文）→ 生成 DLL 需要的纯 ASCII ini
//    · 独立层：由自己的监视进程（--group-filter resident）驱动；默认常开（auto 默认 on），
//      名字层/IP 层的常驻进程不再负责它；排障可用 --group-filter auto off 临时关闭
//    · 命令行：--group-filter status/inject/stop/reload/passthrough/auto/mode/rules/verify/watch/resident
//
//  安全边界（与 _work/gf2/ssf_group_filter2.cpp 一致，任何一项不匹配就失败关闭）：
//    gameui.dll 大小 2325296 / PE 时间戳 0x6A440E8A / SHA-256
//    321EC9B5865582330AF61E81EB347DA31CC213CC6C95B80D6D98170B8A5FBB40
//    入口 RVA 0x49070 的 9 字节 prologue = 55 8B EC 81 EC 84 01 00 00
//    FoundGroupGames 虚表 RVA 0x170A14，vtable[0x480] 必须指向 0x49070，
//    vtable[-1] 必须等于 base+0x1F0EBC（RTTI COL）
//  不改 gameui.dll 文件、不换 VPK、不碰 VAC；stop 只恢复被改的 9 字节。
// ============================================================================

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;

namespace SteamServerFilterIpBlock
{
    internal static class GroupServerFilter
    {
        // ---------------------------------------------------------------- 目标版本指纹
        internal const string ProcessName = "left4dead2";
        internal const string GameUiFile = "gameui.dll";
        internal const string DllFileName = "SSF_GroupFilter2.dll";
        internal const string IniFileName = "SSF_GroupFilter2.ini";
        internal const string ExpectedSha256 = "321EC9B5865582330AF61E81EB347DA31CC213CC6C95B80D6D98170B8A5FBB40";
        internal const uint ExpectedTimestamp = 0x6A440E8A;
        internal const long ExpectedSize = 2325296;
        internal const int TargetRva = 0x49070;
        internal const int PanelVtableRva = 0x170A14;
        internal const int PanelColRva = 0x1F0EBC;
        internal const int InsertSlotOffset = 0x480;
        internal const int PrologueLength = 9;
        internal const int MaxLogDefault = 200000;
        // 安全匹配引擎（_work/gf2/safe_regex.h，有界 Thompson NFA）的硬上限：
        // 宿主在写 ini 前用同一个引擎离线校验，超限/不支持的规则直接拒绝，不把恶意或灾难性正则送进游戏 UI 线程。
        internal const int MaxPatternBytes = 2048;
        internal const int MaxRuleFragments = 128;
        internal const int MaxRuleFragmentBytes = 512;
        internal const int MaxNameLayerFragmentBytes = 512;

        internal static readonly byte[] ExpectedPrologue =
            { 0x55, 0x8B, 0xEC, 0x81, 0xEC, 0x84, 0x01, 0x00, 0x00 };

        // P0-4：事件名带会话 token，防止同会话其它进程伪造 passthrough/stop/status。
        // 原生 DLL 从 ini 的 session_token 读同一 token；token 缺失/不匹配时它拒绝装 Hook（失败关闭）。
        internal const string EventPrefix = @"Local\SSF_GroupFilter2_";
        internal const string EvPassKind = "PassThrough";
        internal const string EvReloadKind = "Reload";
        internal const string EvStopKind = "Stop";
        internal const string ConfigKeyToken = "group-filter-session-token";
        private static string _sessionToken = "";

        internal const string DefaultRulesText =
            "# Steam 组服列表过滤规则（UTF-8，一行一条；可用中文，也可写正则片段）\r\n" +
            "# 作用于「Steam 组战役模式服务器」列表的显示名（Server/name）：命中的行不会出现在列表里。\r\n" +
            "# 所有规则会被包成 ^(规则1|规则2|...)$ 后整串匹配；# 或 ; 开头的行是注释。\r\n" +
            "# 改完保存即可 —— 常驻进程约 1 秒内自动重建 ini，并让已注入的游戏进程立刻重读（不必重启游戏）。\r\n" +
            "^[Pp][Ll][Uu][Ss] L4D2 [0-9][0-9] #[0-9]+$\r\n" +
            "^[Pp][Uu][Rr][Ee] L4D2 .*\r\n" +
            "^纯天然多特战役服.*\r\n" +
            "^纯娱乐.*\r\n";

        private const uint ProcessCreateThread = 0x0002;
        private const uint ProcessQueryInformation = 0x0400;
        private const uint ProcessVmOperation = 0x0008;
        private const uint ProcessVmWrite = 0x0020;
        private const uint ProcessVmRead = 0x0010;
        private const uint ProcessSynchronize = 0x00100000;
        private const uint MemCommit = 0x1000;
        private const uint MemReserve = 0x2000;
        private const uint MemRelease = 0x8000;
        private const uint PageReadWrite = 0x04;
        private const uint Th32SnapModule = 0x00000008;
        private const uint Th32SnapModule32 = 0x00000010;
        private const uint EventModifyState = 0x0002;
        private const uint Infinite = 0xFFFFFFFF;

        internal const string ConfigKeyAuto = "group-filter";
        internal const string ConfigKeyMode = "group-filter-mode";
        internal const string ConfigKeyPass = "group-filter-passthrough";
        internal const string ConfigKeyNameLayer = "group-filter-namelayer";
        internal const string ConfigKeyDedupe = "group-filter-dedupe";

        // ---------------------------------------------------------------- 路径
        internal static string Dir { get { return Path.Combine(IpEngine.Root, "groupfilter"); } }
        internal static string DllPath { get { return Path.Combine(Dir, DllFileName); } }
        internal static string IniPath { get { return Path.Combine(Dir, IniFileName); } }
        // 唯一规则文件：名字层丢包与组服列表删行共用这一份（rules-profiles\custom.txt）
        internal static string RulesPath { get { return SteamServerFilterRules.Engine.CustomFile; } }
        internal static string LastStatusPath { get { return Path.Combine(Dir, "last_status.txt"); } }
        // 组服过滤是独立层：自己的监视进程 + 自己的状态/pid 文件（不占用 --run 的 last_status.txt）
        internal const string ResidentMutexName = @"Local\SSF_GroupFilter2_Resident";
        internal static string ResidentPidPath { get { return Path.Combine(Dir, "resident.pid"); } }
        internal static string ResidentStatusPath { get { return Path.Combine(Dir, "resident_status.txt"); } }
        internal static string LogPathOf(int pid) { return Path.Combine(Path.GetTempPath(), "ssf-gf2-" + pid + ".log"); }
        internal static string StatusPathOf(int pid) { return Path.Combine(Path.GetTempPath(), "ssf-gf2-" + pid + ".status"); }

        // P0-2：注入事务异常时留下的「可能已改写但未受控」标记；存在期间禁止自动重试，直到游戏进程重启。
        internal static string PendingPathOf(int pid) { return Path.Combine(Dir, "pending-" + pid + ".txt"); }
        internal static bool HasPendingTaint(int pid)
        {
            try { return File.Exists(PendingPathOf(pid)); } catch { return false; }
        }
        private static void MarkPendingTaint(int pid, string reason)
        {
            try
            {
                Directory.CreateDirectory(Dir);
                SafeFile.Write(PendingPathOf(pid),
                    "PID=" + pid + "\r\n" +
                    "TIME=" + DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss") + "\r\n" +
                    "REASON=" + (reason ?? "") + "\r\n");
            }
            catch { }
        }
        internal static void ClearPendingTaint(int pid)
        {
            try { File.Delete(PendingPathOf(pid)); } catch { }
        }

        // ---------------------------------------------------------------- 运行期状态
        private static int _tickBusy;
        private static int _lastPid;
        private static DateTime _lastAttempt = DateTime.MinValue;
        private static string _lastInjectError = "";
        private static bool _defaultsWritten;
        private static bool _assetsVerified;
        private static string _embeddedDllSha = "";
        private static DateTime _lastRulesStamp = DateTime.MinValue;
        private static int _lastKnownPid;
        private static int _lastNameLayerTotal;
        private static int _lastNameLayerMerged;
        private static int _lastNameLayerSkipped;
        private static List<string> _lastNameLayerSkipReasons = new List<string>();
        private static bool _residentMode;      // true：本进程是组服过滤监视进程，状态写 resident_status.txt

        internal static bool AutoEnabled
        {
            get
            {
                var s = Config.Get(ConfigKeyAuto);
                if (string.IsNullOrEmpty(s)) return true;   // 默认常开：没有配置键就是开
                return Config.GetBool(ConfigKeyAuto) == true;
            }
        }

        internal static bool FilterMode
        {
            get
            {
                var m = (Config.Get(ConfigKeyMode) ?? "filter").Trim().ToLowerInvariant();
                return m != "diag" && m != "diagnose" && m != "0" && m != "off";
            }
        }

        internal static bool PassThroughEnabled
        {
            get { return Config.GetBool(ConfigKeyPass) == true; }
        }

        /// <summary>同一轮组服列表刷新中，同名（或仅末尾 #编号不同）的服务器只保留第一条（默认开启）。</summary>
        internal static bool DedupeEnabled
        {
            get
            {
                var s = Config.Get(ConfigKeyDedupe);
                if (string.IsNullOrEmpty(s)) return true;   // 新功能默认生效；显式 off 才关闭
                return Config.GetBool(ConfigKeyDedupe) == true;
            }
        }

        // ---------------------------------------------------------------- P0-4 会话 token
        /// <summary>当前会话 token（32 位十六进制）。没有或非法时返回空串。</summary>
        internal static string SessionToken
        {
            get
            {
                if (IsValidToken(_sessionToken)) return _sessionToken;
                var t = (Config.Get(ConfigKeyToken) ?? "").Trim();
                if (IsValidToken(t)) { _sessionToken = t; return t; }
                return "";
            }
        }

        private static bool IsValidToken(string t)
        {
            if (t == null || t.Length != 32) return false;
            foreach (var c in t)
                if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F'))) return false;
            return true;
        }

        private static string NewToken()
        {
            var b = new byte[16];
            using (var rng = RandomNumberGenerator.Create()) rng.GetBytes(b);
            var sb = new StringBuilder(32);
            foreach (var x in b) sb.Append(x.ToString("x2"));
            return sb.ToString();
        }

        /// <summary>确保 config.ini 里有会话 token；返回空串 = 失败（fail-closed）。</summary>
        internal static string EnsureSessionToken(out string err)
        {
            err = "";
            var cur = SessionToken;
            if (cur.Length == 32) return cur;
            try
            {
                var t = NewToken();
                Config.Set(ConfigKeyToken, t);
                _sessionToken = t;
                return t;
            }
            catch (Exception ex) { err = "生成组服会话 token 失败: " + ex.Message; return ""; }
        }

        /// <summary>注入前轮换 token：旧事件/旧状态文件立刻失效，必须先装新 Hook 才能操作。</summary>
        internal static string RotateSessionToken(out string err)
        {
            err = "";
            try
            {
                var t = NewToken();
                Config.Set(ConfigKeyToken, t);
                _sessionToken = t;
                return t;
            }
            catch (Exception ex) { err = "轮换组服会话 token 失败: " + ex.Message; return ""; }
        }

        private static string EventName(string kind)
        {
            var tok = SessionToken;
            if (tok.Length != 32) return "";
            return EventPrefix + tok + "_" + kind;
        }

        /// <summary>兼容旧配置的合并模式开关：规则已经统一到 rules-profiles\custom.txt 一个文件，
        /// 名字层丢包与组服列表删行天然共用同一套规则，本开关不再影响生成结果（只为兼容旧 config.ini 与 --group-filter namelayer）。</summary>
        internal static string NameLayerMode
        {
            get
            {
                var m = (Config.Get(ConfigKeyNameLayer) ?? "custom").Trim().ToLowerInvariant();
                if (m == "off" || m == "0" || m == "false" || m == "no" || m == "none") return "off";
                if (m == "all" || m == "on" || m == "1" || m == "true" || m == "yes") return "all";
                return "custom";
            }
        }

        internal static string NameLayerModeText()
        {
            return "已统一（规则只在 rules-profiles\\custom.txt，名字层与组服列表过滤共用；旧档位开关已不生效）";
        }

        // ================================================================ 资源解包
        private static byte[] EmbeddedDll()
        {
            var asm = typeof(GroupServerFilter).Assembly;
            using (var s = asm.GetManifestResourceStream("GroupFilterDll"))
            {
                if (s == null) return null;
                using (var ms = new MemoryStream())
                {
                    s.CopyTo(ms);
                    return ms.ToArray();
                }
            }
        }

        internal static string Sha256Of(byte[] data)
        {
            using (var sha = SHA256.Create())
            {
                var h = sha.ComputeHash(data);
                var sb = new StringBuilder(h.Length * 2);
                foreach (var b in h) sb.Append(b.ToString("X2"));
                return sb.ToString();
            }
        }

        internal static string Sha256OfFile(string path)
        {
            try
            {
                using (var sha = SHA256.Create())
                using (var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite))
                {
                    var h = sha.ComputeHash(fs);
                    var sb = new StringBuilder(h.Length * 2);
                    foreach (var b in h) sb.Append(b.ToString("X2"));
                    return sb.ToString();
                }
            }
            catch { return ""; }
        }

        /// <summary>把内嵌 DLL 与默认规则文件准备到磁盘；返回 false 时 err 有原因。</summary>
        internal static bool EnsureAssets(out string err)
        {
            err = "";
            try
            {
                Directory.CreateDirectory(Dir);
                // 规则只有一份统一文件（rules-profiles\custom.txt）：首次运行/升级时在这里做一次幂等迁移，
                // 旧的多档位规则文件与 group_filter_rules.txt 会被归档到 rules-profiles\archive\。
                try { SteamServerFilterRules.Engine.EnsureUnifiedRules(); } catch { }
                WriteDefaultConfigKeys();

                var embedded = EmbeddedDll();
                if (embedded == null || embedded.Length < 1024)
                {
                    err = "内嵌原生 DLL 缺失（请用 build.cmd 重新编译 FilterTool.exe）";
                    return false;
                }
                if (_embeddedDllSha.Length == 0) _embeddedDllSha = Sha256Of(embedded);

                bool need = !File.Exists(DllPath) || new FileInfo(DllPath).Length != embedded.Length;
                if (!need && !_assetsVerified)
                {
                    // 大小一致也再比一次哈希，防止磁盘上留着旧构建
                    need = !string.Equals(Sha256OfFile(DllPath), _embeddedDllSha, StringComparison.OrdinalIgnoreCase);
                }
                if (need)
                {
                    var tmp = DllPath + ".tmp" + Process.GetCurrentProcess().Id;
                    File.WriteAllBytes(tmp, embedded);
                    try
                    {
                        File.Copy(tmp, DllPath, true);
                    }
                    catch
                    {
                        // 游戏正在使用旧 DLL 时覆盖会失败（文件被映射）：保留旧文件，本次注入会失败关闭
                        if (!File.Exists(DllPath)) throw;
                    }
                    finally { try { File.Delete(tmp); } catch { } }
                }
                _assetsVerified = true;
                return true;
            }
            catch (Exception ex)
            {
                err = ex.Message;
                return false;
            }
        }

        private static void WriteDefaultConfigKeys()
        {
            if (_defaultsWritten) return;
            _defaultsWritten = true;
            if (Config.Get(ConfigKeyAuto) == null) Config.Set(ConfigKeyAuto, "on");    // 独立层默认常开
            if (Config.Get(ConfigKeyMode) == null) Config.Set(ConfigKeyMode, "filter");
            if (Config.Get(ConfigKeyPass) == null) Config.Set(ConfigKeyPass, "off");
            if (Config.Get(ConfigKeyNameLayer) == null) Config.Set(ConfigKeyNameLayer, "custom");
            if (Config.Get(ConfigKeyDedupe) == null) Config.Set(ConfigKeyDedupe, "on");
        }

        // ================================================================ 规则 → ini
        /// <summary>把非 ASCII 字符按 UTF-8 字节转成 \xHH，保证 ini 始终是纯 ASCII。</summary>
        internal static string AsciiEscape(string s)
        {
            var sb = new StringBuilder();
            foreach (var ch in s)
            {
                if (ch <= 0x7F) { sb.Append(ch); continue; }
                var bytes = Encoding.UTF8.GetBytes(ch.ToString());
                foreach (var b in bytes) sb.Append(@"\x").Append(b.ToString("X2"));
            }
            return sb.ToString();
        }

        // ================================================================ 原生安全匹配引擎
        // 钩子里的匹配用 _work/gf2/safe_regex.h 的有界 NFA（无回溯、O(状态数×长度)）；
        // 宿主侧复用同一引擎做离线校验：规则写进 ini 之前就被拒绝，游戏线程不会执行不安全的正则。
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        private delegate int ValidatePatternFn(IntPtr pattern, IntPtr err, int errCch);

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        private delegate int TestMatchFn(IntPtr pattern, IntPtr text);

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        private delegate void DedupeResetFn();

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        private delegate int DedupeCheckFn(IntPtr name);

        private static IntPtr _nativeModule;
        private static ValidatePatternFn _nativeValidate;
        private static TestMatchFn _nativeTestMatch;
        private static DedupeResetFn _nativeDedupeReset;
        private static DedupeCheckFn _nativeDedupeCheck;

        private static bool EnsureNativeValidator(out string err)
        {
            err = "";
            if (_nativeValidate != null) return true;
            try
            {
                if (!EnsureAssets(out err)) return false;
                if (_nativeModule == IntPtr.Zero)
                {
                    _nativeModule = LoadLibraryW(DllPath);
                    if (_nativeModule == IntPtr.Zero)
                    {
                        err = "加载原生过滤 DLL 失败（错误 " + Marshal.GetLastWin32Error() + "）：" + DllPath;
                        return false;
                    }
                }
                var pv = GetProcAddress(_nativeModule, "SSF_ValidatePattern");
                if (pv == IntPtr.Zero) pv = GetProcAddress(_nativeModule, "_SSF_ValidatePattern");
                if (pv == IntPtr.Zero)
                {
                    err = "原生 DLL 缺少 SSF_ValidatePattern 导出，请重新构建 _work/gf2/SSF_GroupFilter2.dll";
                    return false;
                }
                _nativeValidate = (ValidatePatternFn)Marshal.GetDelegateForFunctionPointer(pv, typeof(ValidatePatternFn));
                var pm = GetProcAddress(_nativeModule, "SSF_TestMatch");
                if (pm == IntPtr.Zero) pm = GetProcAddress(_nativeModule, "_SSF_TestMatch");
                if (pm != IntPtr.Zero)
                    _nativeTestMatch = (TestMatchFn)Marshal.GetDelegateForFunctionPointer(pm, typeof(TestMatchFn));
                var dr = GetProcAddress(_nativeModule, "SSF_DedupeReset");
                if (dr == IntPtr.Zero) dr = GetProcAddress(_nativeModule, "_SSF_DedupeReset");
                if (dr != IntPtr.Zero)
                    _nativeDedupeReset = (DedupeResetFn)Marshal.GetDelegateForFunctionPointer(dr, typeof(DedupeResetFn));
                var dc = GetProcAddress(_nativeModule, "SSF_DedupeCheck");
                if (dc == IntPtr.Zero) dc = GetProcAddress(_nativeModule, "_SSF_DedupeCheck");
                if (dc != IntPtr.Zero)
                    _nativeDedupeCheck = (DedupeCheckFn)Marshal.GetDelegateForFunctionPointer(dc, typeof(DedupeCheckFn));
                return true;
            }
            catch (Exception ex) { err = ex.Message; return false; }
        }

        private static IntPtr AllocAnsi(string s)
        {
            var bytes = Encoding.UTF8.GetBytes((s ?? "") + "\0");
            var block = Marshal.AllocHGlobal(bytes.Length);
            Marshal.Copy(bytes, 0, block, bytes.Length);
            return block;
        }

        /// <summary>用与钩子完全相同的安全引擎校验生成的正则；超过硬上限或引擎不支持时返回 false。</summary>
        internal static bool NativeValidateRegex(string pattern, out string err)
        {
            err = "";
            if (pattern == null) pattern = "";
            int bytes = Encoding.UTF8.GetByteCount(pattern);
            if (bytes > MaxPatternBytes)
            {
                err = "生成的正则 " + bytes + " 字节，超过安全上限 " + MaxPatternBytes + " 字节";
                return false;
            }
            if (!EnsureNativeValidator(out err)) return false;
            IntPtr pb = IntPtr.Zero, eb = IntPtr.Zero;
            try
            {
                pb = AllocAnsi(pattern);
                eb = Marshal.AllocHGlobal(512);
                for (int i = 0; i < 512; i++) Marshal.WriteByte(eb, i, 0);
                if (_nativeValidate(pb, eb, 512) == 0)
                {
                    var reason = Marshal.PtrToStringAnsi(eb) ?? "";
                    err = "安全匹配引擎拒绝该规则: " + reason;
                    return false;
                }
                return true;
            }
            catch (Exception ex) { err = ex.Message; return false; }
            finally
            {
                if (pb != IntPtr.Zero) Marshal.FreeHGlobal(pb);
                if (eb != IntPtr.Zero) Marshal.FreeHGlobal(eb);
            }
        }

        /// <summary>测试用：用安全引擎做整串匹配。-1 = 规则无效；0/1 = 不匹配/匹配。</summary>
        internal static int NativeTestMatch(string pattern, string text, out string err)
        {
            err = "";
            if (!EnsureNativeValidator(out err)) return -1;
            if (_nativeTestMatch == null) { err = "原生 DLL 缺少 SSF_TestMatch 导出"; return -1; }
            IntPtr pb = IntPtr.Zero, tb = IntPtr.Zero;
            try
            {
                pb = AllocAnsi(pattern);
                tb = AllocAnsi(text);
                return _nativeTestMatch(pb, tb);
            }
            catch (Exception ex) { err = ex.Message; return -1; }
            finally
            {
                if (pb != IntPtr.Zero) Marshal.FreeHGlobal(pb);
                if (tb != IntPtr.Zero) Marshal.FreeHGlobal(tb);
            }
        }

        /// <summary>自检用：重置原生去重表（等价于新一轮组服列表刷新）。</summary>
        internal static bool NativeDedupeReset(out string err)
        {
            err = "";
            if (!EnsureNativeValidator(out err)) return false;
            if (_nativeDedupeReset == null) { err = "原生 DLL 缺少 SSF_DedupeReset 导出"; return false; }
            try { _nativeDedupeReset(); return true; }
            catch (Exception ex) { err = ex.Message; return false; }
        }

        /// <summary>自检用：向原生去重表查询一个名字；0 = 首次出现，1 = 本轮已出现（重复），-1 = 失败。</summary>
        internal static int NativeDedupeCheck(string name, out string err)
        {
            err = "";
            if (!EnsureNativeValidator(out err)) return -1;
            if (_nativeDedupeCheck == null) { err = "原生 DLL 缺少 SSF_DedupeCheck 导出"; return -1; }
            IntPtr pb = IntPtr.Zero;
            try
            {
                pb = AllocAnsi(name);
                return _nativeDedupeCheck(pb);
            }
            catch (Exception ex) { err = ex.Message; return -1; }
            finally { if (pb != IntPtr.Zero) Marshal.FreeHGlobal(pb); }
        }

        /// <summary>读统一规则文件 rules-profiles\custom.txt 生成整串匹配的正则；空规则返回空串（不拦任何行）。
        /// 统一规则是名字层的「子串匹配裸正则」，这里包成 .*(?:规则).* 作为等价分支，
        /// 这样同一个名字在名字层丢包、也在 Steam 组服列表里被删行。</summary>
        internal static bool BuildRegex(out string regex, out string err)
        {
            return BuildRegexEx(out regex, out err, out _lastNameLayerTotal, out _lastNameLayerMerged,
                                out _lastNameLayerSkipped, out _lastNameLayerSkipReasons);
        }

        internal static bool BuildRegexEx(out string regex, out string err,
                                          out int nameLayerTotal, out int nameLayerMerged,
                                          out int nameLayerSkipped, out List<string> skipReasons)
        {
            regex = "";
            err = "";
            nameLayerTotal = 0;
            nameLayerMerged = 0;
            nameLayerSkipped = 0;
            skipReasons = new List<string>();
            try
            {
                // 统一规则文件：名字层丢包与组服列表删行共用 rules-profiles\custom.txt 这一套规则。
                var customFile = SteamServerFilterRules.Engine.CustomFile;
                if (!File.Exists(customFile)) { err = "统一规则文件不存在: " + customFile; return false; }
                // 用 ReadUnifiedRules 而不是 ReadProfileRules：要能看到「仅名字层」标记段，
                // 段内的规则只给名字层丢包用，不参与这里生成组服列表删行正则。
                List<SteamServerFilterRules.Engine.UnifiedRule> rules;
                try { rules = SteamServerFilterRules.Engine.ReadUnifiedRules(); }
                catch (Exception ex) { err = "读取统一规则文件失败: " + ex.Message; return false; }

                var frags = new List<string>();
                // 同一个名字被加两次时只保留一个分支
                var seenFrags = new HashSet<string>(StringComparer.Ordinal);
                foreach (var r0 in rules)
                {
                    nameLayerTotal++;
                    var rule = (r0 == null || r0.Rule == null) ? "" : r0.Rule.Trim();
                    if (rule.Length == 0) continue;
                    if (r0 != null && !r0.GroupFilter)
                    {
                        nameLayerSkipped++;
                        skipReasons.Add(rule + "  ->  仅名字层（勾选「同时加入组服列表过滤名称」才会从组服列表删行）");
                        continue;
                    }
                    string why;
                    var frag = NameLayerRuleToGroupFragment(rule, out why);
                    if (frag == null)
                    {
                        nameLayerSkipped++;
                        skipReasons.Add(rule + "  ->  " + why);
                        continue;
                    }
                    if (Encoding.UTF8.GetByteCount(frag) > MaxNameLayerFragmentBytes)
                    {
                        nameLayerSkipped++;
                        skipReasons.Add(rule + "  ->  规则过长（" + Encoding.UTF8.GetByteCount(frag) + " 字节，上限 " + MaxNameLayerFragmentBytes + "）");
                        continue;
                    }
                    var escFrag = AsciiEscape(frag);
                    if (!seenFrags.Add(escFrag)) continue;
                    frags.Add(escFrag);
                    nameLayerMerged++;
                }

                if (frags.Count == 0) return true;      // 空规则 = 不过滤
                if (frags.Count > MaxRuleFragments)
                {
                    err = "规则条数 " + frags.Count + " 超过上限 " + MaxRuleFragments + "（请合并/精简统一规则文件 rules-profiles\\custom.txt）";
                    return false;
                }
                var pattern = "^(" + string.Join("|", frags.ToArray()) + ")$";
                try { new Regex(pattern); }
                catch (Exception ex) { err = "规则语法错误（生成的正则无法解析）: " + ex.Message; return false; }
                string nerr;
                if (!NativeValidateRegex(pattern, out nerr))
                {
                    err = "规则被安全匹配引擎拒绝：" + nerr;
                    return false;
                }
                regex = pattern;
                return true;
            }
            catch (Exception ex) { err = ex.Message; return false; }
        }

        // （旧的 AppendNameRule / ReadNameLayerRuleList 已删除：规则统一写在 rules-profiles\custom.txt，
        //  名字层丢包与组服列表删行共用，不再需要单独的组服规则文件。）
        /// <summary>把名字层的一条「子串匹配裸正则」转成组服整串正则里的分支：.*(?:规则).*。
        /// 原生 std::regex(ECMAScript) 不支持 (?i) 和部分 .NET 构造，这里做大小写展开或跳过；
        /// 返回 null 表示跳过，why 说明原因（会写进 --group-filter rules / status）。</summary>
        internal static string NameLayerRuleToGroupFragment(string rule, out string why)
        {
            why = "";
            var r = (rule ?? "").Trim();
            if (r.Length == 0) { why = "空规则"; return null; }
            if (r.IndexOf('\uFFFD') >= 0) { why = "规则里有乱码 U+FFFD（规则档不是 UTF-8）"; return null; }

            // 扫一遍转义：\p{...} \A \Z \z \G \k \Q 等都是 .NET 专有，原生 std::regex 不支持
            for (int i = 0; i + 1 < r.Length; i++)
            {
                if (r[i] != '\\') continue;
                var c = r[i + 1];
                if (c == 'p' || c == 'P' || c == 'A' || c == 'Z' || c == 'z' || c == 'G' || c == 'k' || c == 'Q')
                {
                    why = "用了 .NET 专有正则构造 \\" + c + "，安全匹配引擎不支持";
                    return null;
                }
                if (c >= '1' && c <= '9')
                {
                    why = "含反向引用 \\" + c + "，安全匹配引擎不支持";
                    return null;
                }
                i++;      // 跳过被转义的字符，避免把 \\A 误判成 \A
            }

            var folded = r;
            if (folded.IndexOf("(?i)", StringComparison.Ordinal) >= 0)
            {
                folded = folded.Replace("(?i)", "");
                folded = AsciiCaseFold(folded);
            }
            // 剩下的内联 (?...) 只允许非捕获组 / 前瞻 / 负前瞻
            for (int i = 0; i + 1 < folded.Length; i++)
            {
                if (folded[i] != '(' || folded[i + 1] != '?') continue;
                var c = i + 2 < folded.Length ? folded[i + 2] : '\0';
                if (c != ':')
                {
                    why = "含 lookaround/内联构造 (?…)，安全匹配引擎不支持";
                    return null;
                }
            }

            var frag = ".*(?:" + folded + ").*";
            try { new Regex("^(?:" + frag + ")$"); }
            catch (Exception ex) { why = "规则语法错误: " + ex.Message; return null; }
            string gerr;
            if (!NativeValidateRegex("^(?:" + frag + ")$", out gerr))
            {
                why = "安全匹配引擎不接受该规则: " + gerr;
                return null;
            }
            return frag;
        }

        /// <summary>把字符类之外的 ASCII 字母展开成 [Xx]，等价于 (?i)（原生 std::regex 不支持内联标志）。</summary>
        internal static string AsciiCaseFold(string rule)
        {
            var sb = new StringBuilder(rule.Length * 2);
            bool inClass = false;
            for (int i = 0; i < rule.Length; i++)
            {
                var ch = rule[i];
                if (ch == '\\' && i + 1 < rule.Length)
                {
                    sb.Append(ch).Append(rule[i + 1]);
                    i++;
                    continue;
                }
                if (inClass)
                {
                    sb.Append(ch);
                    if (ch == ']') inClass = false;
                    continue;
                }
                if (ch == '[') { inClass = true; sb.Append(ch); continue; }
                if ((ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z'))
                {
                    sb.Append('[').Append(char.ToUpperInvariant(ch)).Append(char.ToLowerInvariant(ch)).Append(']');
                    continue;
                }
                sb.Append(ch);
            }
            return sb.ToString();
        }

        internal static string BuildIniText(bool filterMode, string regex)
        {
            return BuildIniText(filterMode, regex, SessionToken);
        }

        internal static string BuildIniText(bool filterMode, string regex, string sessionToken)
        {
            var sb = new StringBuilder();
            sb.AppendLine("[groupfilter]");
            sb.AppendLine("; 本文件由 FilterTool 从统一规则文件 rules-profiles\\custom.txt 自动生成，请改规则文件后执行 reload。");
            sb.AppendLine("filter=" + (filterMode ? "1" : "0"));
            sb.AppendLine("regex=" + regex);
            // 1 = 每一遍重建中同名（含仅末尾 #编号不同）只保留第一条；0 = 全部保留
            sb.AppendLine("dedupe_names=" + (DedupeEnabled ? "1" : "0"));
            sb.AppendLine("max_log=" + MaxLogDefault);
            sb.AppendLine("expected_sha256=" + ExpectedSha256);
            sb.AppendLine("expected_timestamp=0x" + ExpectedTimestamp.ToString("X"));
            sb.AppendLine("expected_size=" + ExpectedSize);
            // P0-4：原生 DLL 用这个 token 命名事件、写状态；缺了它拒绝注入（fail-closed）
            sb.AppendLine("session_token=" + (sessionToken ?? ""));
            return sb.ToString();
        }

        /// <summary>重建 ini（仅在内容变化时落盘）。changed=true 表示变了、需要让已注入的 DLL reload。</summary>
        internal static bool ApplyIni(out bool changed, out string err)
        {
            changed = false;
            err = "";
            try
            {
                if (!EnsureAssets(out err)) return false;
                string regex;
                if (!BuildRegex(out regex, out err)) return false;
                var token = EnsureSessionToken(out err);
                if (token.Length != 32) return false;
                var text = BuildIniText(FilterMode, regex, token);
                var old = SafeFile.Read(IniPath).Replace("\r\n", "\n").Replace('\r', '\n');
                if (!string.Equals(old.Trim(), text.Replace("\r\n", "\n").Trim(), StringComparison.Ordinal))
                {
                    SafeFile.Write(IniPath, text);
                    changed = true;
                }
                return true;
            }
            catch (Exception ex) { err = ex.Message; return false; }
        }

        // ================================================================ 进程 / 模块
        internal sealed class ModuleInfo
        {
            public string Name = "";
            public string Path = "";
            public IntPtr Base = IntPtr.Zero;
            public uint Size;
        }

        internal static bool TryGetModules(int pid, out List<ModuleInfo> mods)
        {
            mods = new List<ModuleInfo>();
            var snap = CreateToolhelp32Snapshot(Th32SnapModule | Th32SnapModule32, pid);
            if (snap == IntPtr.Zero || snap == (IntPtr)(-1)) return false;
            try
            {
                var me = new MODULEENTRY32W();
                me.dwSize = (uint)Marshal.SizeOf(typeof(MODULEENTRY32W));
                if (!Module32FirstW(snap, ref me)) return false;
                do
                {
                    mods.Add(new ModuleInfo
                    {
                        Name = me.szModule ?? "",
                        Path = me.szExePath ?? "",
                        Base = me.modBaseAddr,
                        Size = me.modBaseSize
                    });
                } while (Module32NextW(snap, ref me));
                return true;
            }
            finally { CloseHandle(snap); }
        }

        internal static ModuleInfo FindModule(int pid, string fileName)
        {
            List<ModuleInfo> mods;
            if (!TryGetModules(pid, out mods)) return null;
            foreach (var m in mods)
                if (string.Equals(m.Name, fileName, StringComparison.OrdinalIgnoreCase)) return m;
            return null;
        }

        internal static Process FindGameProcess()
        {
            try
            {
                foreach (var p in Process.GetProcessesByName(ProcessName))
                {
                    try
                    {
                        List<ModuleInfo> mods;
                        if (TryGetModules(p.Id, out mods) &&
                            mods.Any(m => string.Equals(m.Name, ProcessName + ".exe", StringComparison.OrdinalIgnoreCase)))
                            return p;
                    }
                    catch { }
                }
            }
            catch { }
            return null;
        }

        internal static string GameDir
        {
            get
            {
                try { return GroupListDiagnostics.FindInstallPath(null); }
                catch { return null; }
            }
        }

        internal static string GameUiPathIn(string gameDir)
        {
            if (string.IsNullOrEmpty(gameDir)) return null;
            return Path.Combine(gameDir, "bin", GameUiFile);
        }

        // ================================================================ PE 导出解析（本地 DLL 文件）
        private static int RvaToOffset(byte[] data, int peOff, int rva)
        {
            int fileHeader = peOff + 4;
            int numSections = BitConverter.ToUInt16(data, fileHeader + 2);
            int sizeOpt = BitConverter.ToUInt16(data, fileHeader + 16);
            int sections = fileHeader + 20 + sizeOpt;
            for (int i = 0; i < numSections; i++)
            {
                int s = sections + i * 40;
                int va = BitConverter.ToInt32(data, s + 12);
                int rawSize = BitConverter.ToInt32(data, s + 16);
                int rawPtr = BitConverter.ToInt32(data, s + 20);
                if (rva >= va && rva < va + Math.Max(rawSize, 1)) return rawPtr + (rva - va);
            }
            return -1;
        }

        private static string ReadAsciiZ(byte[] data, int off)
        {
            if (off < 0 || off >= data.Length) return "";
            int end = off;
            while (end < data.Length && data[end] != 0 && end - off < 256) end++;
            return Encoding.ASCII.GetString(data, off, end - off);
        }

        internal static bool TryGetExportRva(string fileName, string exportName, out int rva, out string err)
        {
            rva = 0;
            err = "";
            try
            {
                var data = File.ReadAllBytes(fileName);
                if (data.Length < 0x40 || data[0] != (byte)'M' || data[1] != (byte)'Z') { err = "不是 PE 文件"; return false; }
                int peOff = BitConverter.ToInt32(data, 0x3C);
                if (peOff <= 0 || peOff + 24 >= data.Length) { err = "PE 头越界"; return false; }
                int fileHeader = peOff + 4;
                int machine = BitConverter.ToUInt16(data, fileHeader);
                int optStart = fileHeader + 20;
                int magic = BitConverter.ToUInt16(data, optStart);
                if (magic != 0x10B) { err = "不是 PE32（x86）"; return false; }
                int dataDir = optStart + 96;
                int exportRva = BitConverter.ToInt32(data, dataDir);
                int exportSize = BitConverter.ToInt32(data, dataDir + 4);
                if (exportRva == 0 || exportSize == 0) { err = "没有导出表"; return false; }
                int ed = RvaToOffset(data, peOff, exportRva);
                if (ed < 0) { err = "导出表 RVA 无法映射"; return false; }
                int numNames = BitConverter.ToInt32(data, ed + 24);
                int addrFunctions = BitConverter.ToInt32(data, ed + 28);
                int addrNames = BitConverter.ToInt32(data, ed + 32);
                int addrOrds = BitConverter.ToInt32(data, ed + 36);
                int namesOff = RvaToOffset(data, peOff, addrNames);
                int funcsOff = RvaToOffset(data, peOff, addrFunctions);
                int ordsOff = RvaToOffset(data, peOff, addrOrds);
                if (namesOff < 0 || funcsOff < 0 || ordsOff < 0) { err = "导出表成员无法映射"; return false; }
                for (int i = 0; i < numNames; i++)
                {
                    int nameRva = BitConverter.ToInt32(data, namesOff + i * 4);
                    int nameOff = RvaToOffset(data, peOff, nameRva);
                    var nm = ReadAsciiZ(data, nameOff);
                    // 32 位 C++ 导出名会带修饰（实测 SSF_Start 导出为 _SSF_Start@4），按“包含”匹配
                    if (nm.IndexOf(exportName, StringComparison.Ordinal) < 0) continue;
                    int ord = BitConverter.ToUInt16(data, ordsOff + i * 2);
                    int funcRva = BitConverter.ToInt32(data, funcsOff + ord * 4);
                    if (funcRva == 0) { err = "导出函数为空"; return false; }
                    rva = funcRva;
                    return true;
                }
                err = "没找到导出 " + exportName;
                return false;
            }
            catch (Exception ex) { err = ex.Message; return false; }
        }

        // ================================================================ 只读门禁
        internal sealed class VerifyResult
        {
            public bool Ok;
            public string Error = "";
            public int Pid;
            public string ImagePath = "";
            public string GameDir = "";
            public string GameUiPath = "";
            public long Size;
            public uint Timestamp;
            public string Sha256 = "";
            public bool FileSizeOk, FileTimestampOk, FileHashOk;
            public IntPtr GameUiBase = IntPtr.Zero;
            public string RemoteGameUiPath = "";
            public bool RemoteModuleOk, PrologueOk, VtableOk;
            public bool HookPatched; // 入口已是 E9 跳转补丁（Hook 已装）；Verify 不该把它当版本不匹配
            public bool DllLoaded, HookInstalled;
            public string HookMode = "";
            public string HookStatus = "";
            public List<string> Lines = new List<string>();
        }

        internal static Dictionary<string, string> ReadStatusFile(int pid)
        {
            var d = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            var text = SafeFile.Read(StatusPathOf(pid));
            foreach (var raw in text.Replace("\r\n", "\n").Split('\n'))
            {
                var line = raw.Trim();
                if (line.Length == 0) continue;
                var eq = line.IndexOf('=');
                if (eq <= 0) continue;
                var k = line.Substring(0, eq).Trim();
                var v = line.Substring(eq + 1).Trim();
                if (k.Length > 0) d[k] = v;
            }
            return d;
        }

        internal static bool HookInstalled(int pid)
        {
            var st = ReadStatusFile(pid);
            string res;
            if (!st.TryGetValue("RESULT", out res)) return false;
            string hook;
            if (!st.TryGetValue("HOOK", out hook)) return false;
            if (!string.Equals(hook, "installed", StringComparison.OrdinalIgnoreCase)) return false;
            if (!res.StartsWith("OK_", StringComparison.OrdinalIgnoreCase)) return false;
            // P0-4：状态文件必须带本次会话 token 与目标 pid，否则视为伪造/过期（fail-closed）
            string tok, spid;
            if (!st.TryGetValue("TOKEN", out tok)) return false;
            if (!st.TryGetValue("PID", out spid)) return false;
            if (!string.Equals(tok.Trim(), SessionToken, StringComparison.OrdinalIgnoreCase)) return false;
            int s;
            return int.TryParse(spid.Trim(), out s) && s == pid;
        }

        internal static VerifyResult Verify(bool readRemote)
        {
            var v = new VerifyResult();
            try
            {
                var p = FindGameProcess();
                if (p == null)
                {
                    v.Error = "没找到正在运行的 left4dead2.exe（请先启动游戏）";
                    return v;
                }
                v.Pid = p.Id;
                v.ImagePath = SafeProcessImage(p);
                var gameDir = GameDir;
                v.GameDir = gameDir ?? "";
                if (string.IsNullOrEmpty(gameDir))
                {
                    v.Error = "没找到 Left 4 Dead 2 安装目录（Steam 库）";
                    return v;
                }
                var gameui = GameUiPathIn(gameDir);
                v.GameUiPath = gameui ?? "";
                if (gameui == null || !File.Exists(gameui))
                {
                    v.Error = "gameui.dll 不存在: " + v.GameUiPath;
                    return v;
                }
                v.Size = new FileInfo(gameui).Length;
                v.Timestamp = ReadPeTimestamp(gameui);
                v.Sha256 = Sha256OfFile(gameui);
                v.FileSizeOk = v.Size == ExpectedSize;
                v.FileTimestampOk = v.Timestamp == ExpectedTimestamp;
                v.FileHashOk = string.Equals(v.Sha256, ExpectedSha256, StringComparison.OrdinalIgnoreCase);

                var remote = FindModule(v.Pid, GameUiFile);
                v.DllLoaded = FindModule(v.Pid, DllFileName) != null;
                var st = ReadStatusFile(v.Pid);
                string res, mode;
                if (st.TryGetValue("RESULT", out res)) v.HookStatus = res;
                if (st.TryGetValue("MODE", out mode)) v.HookMode = mode;
                v.HookInstalled = HookInstalled(v.Pid);

                v.Lines.Add("游戏进程: pid=" + v.Pid + " image=" + v.ImagePath);
                v.Lines.Add("游戏目录: " + v.GameDir);
                v.Lines.Add("gameui.dll: " + v.GameUiPath);
                v.Lines.Add("  大小 " + v.Size + (v.FileSizeOk ? " ✓" : " ✗ 期望 " + ExpectedSize));
                v.Lines.Add("  PE 时间戳 0x" + v.Timestamp.ToString("X") + (v.FileTimestampOk ? " ✓" : " ✗ 期望 0x" + ExpectedTimestamp.ToString("X")));
                v.Lines.Add("  SHA-256 " + (v.FileHashOk ? "匹配 ✓" : "不匹配 ✗") + "  " + v.Sha256);
                if (!v.FileSizeOk || !v.FileTimestampOk || !v.FileHashOk)
                {
                    v.Error = "gameui.dll 指纹不匹配：这个游戏版本不在已验证列表里（失败关闭，不注入）";
                    return v;
                }

                if (remote == null)
                {
                    v.Error = "游戏进程里还没加载 gameui.dll（等主菜单出来再试）";
                    return v;
                }
                v.GameUiBase = remote.Base;
                v.RemoteGameUiPath = remote.Path;
                v.RemoteModuleOk = true;
                v.Lines.Add("远端模块: gameui.dll base=0x" + remote.Base.ToInt64().ToString("X8") + " size=0x" + remote.Size.ToString("X8") +
                            " path=" + remote.Path);
                if (!string.Equals(Path.GetFullPath(remote.Path), Path.GetFullPath(gameui), StringComparison.OrdinalIgnoreCase))
                    v.Lines.Add("  注意: 远端路径与安装目录不一致（可能是另一份拷贝）");

                if (readRemote)
                {
                    var handle = OpenProcess(ProcessVmRead | ProcessQueryInformation, false, v.Pid);
                    if (handle == IntPtr.Zero)
                    {
                        v.Error = "OpenProcess 失败: " + Marshal.GetLastWin32Error();
                        return v;
                    }
                    try
                    {
                        var target = IntPtr.Add(remote.Base, TargetRva);
                        var pro = ReadBytes(handle, target, PrologueLength);
                        bool proOriginal = pro != null && pro.SequenceEqual(ExpectedPrologue);
                        v.HookPatched = pro != null && !proOriginal && pro[0] == 0xE9;
                        v.PrologueOk = proOriginal || v.HookPatched;
                        var vt = IntPtr.Add(remote.Base, PanelVtableRva);
                        var slot = ReadBytes(handle, IntPtr.Add(vt, InsertSlotOffset), 4);
                        var col = ReadBytes(handle, IntPtr.Add(vt, -4), 4);
                        long slotVal = slot != null && slot.Length == 4 ? BitConverter.ToUInt32(slot, 0) : 0;
                        long colVal = col != null && col.Length == 4 ? BitConverter.ToUInt32(col, 0) : 0;
                        long expectTarget = (long)target;
                        long expectCol = (long)IntPtr.Add(remote.Base, PanelColRva);
                        v.VtableOk = slotVal == expectTarget && colVal == expectCol;
                        v.Lines.Add("入口 prologue @" + Hex(target) + ": " +
                                    (proOriginal ? "原始字节匹配 ✓" : v.HookPatched ? "已装 Hook（E9 跳转补丁）✓" : "不匹配 ✗"));
                        v.Lines.Add("虚表校验: slot[0x480]=" + Hex((IntPtr)slotVal) + " COL=" + Hex((IntPtr)colVal) +
                                    (v.VtableOk ? " ✓" : " ✗"));
                        if (!v.PrologueOk || !v.VtableOk)
                        {
                            v.Error = "运行时字节/虚表校验失败（游戏可能已更新，失败关闭）";
                            return v;
                        }
                    }
                    finally { CloseHandle(handle); }
                }

                v.Lines.Add("DLL 已加载: " + (v.DllLoaded ? "是" : "否") + " · Hook 状态: " +
                            (v.HookInstalled ? "已安装（" + (v.HookMode.Length > 0 ? v.HookMode : "?") + "）" : (v.HookStatus.Length > 0 ? v.HookStatus : "未安装")));
                v.Ok = true;
                return v;
            }
            catch (Exception ex)
            {
                v.Error = ex.Message;
                return v;
            }
        }

        private static string SafeProcessImage(Process p)
        {
            try { return p.MainModule.FileName; }
            catch
            {
                try
                {
                    var h = OpenProcess(ProcessQueryInformation, false, p.Id);
                    if (h == IntPtr.Zero) return "";
                    try
                    {
                        var sb = new StringBuilder(1024);
                        int size = sb.Capacity;
                        if (QueryFullProcessImageNameW(h, 0, sb, ref size)) return sb.ToString();
                    }
                    finally { CloseHandle(h); }
                }
                catch { }
                return "";
            }
        }

        private static uint ReadPeTimestamp(string path)
        {
            try
            {
                using (var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite))
                {
                    var buf = new byte[0x400];
                    int n = fs.Read(buf, 0, buf.Length);
                    if (n < 0x40) return 0;
                    int peOff = BitConverter.ToInt32(buf, 0x3C);
                    if (peOff <= 0 || peOff + 12 > n) return 0;
                    return BitConverter.ToUInt32(buf, peOff + 8);
                }
            }
            catch { return 0; }
        }

        internal static string Hex(IntPtr p) { return "0x" + p.ToInt64().ToString("X8"); }

        private static byte[] ReadBytes(IntPtr handle, IntPtr addr, int count)
        {
            var buf = new byte[count];
            IntPtr read;
            if (!ReadProcessMemory(handle, addr, buf, count, out read)) return null;
            if (read.ToInt64() != count) return null;
            return buf;
        }

        // ================================================================ 注入 / 停止 / 重载
        internal static bool InjectNow(out string report)
        {
            var lines = new List<string>();
            report = "";
            try
            {
                var v = Verify(true);
                if (!v.Ok)
                {
                    report = v.Error;
                    return false;
                }
                if (v.HookInstalled)
                {
                    report = "已经注入并生效（pid=" + v.Pid + "，模式 " + v.HookMode + "），无需重复注入。";
                    return true;
                }
                if (HasPendingTaint(v.Pid))
                {
                    report = "该游戏进程上次注入异常且回滚未确认（标记文件 " + PendingPathOf(v.Pid) +
                             "）。为安全起见不再自动/手动注入，请重启游戏；确认无风险后可手动删除该标记文件。";
                    return false;
                }
                if (v.HookPatched)
                {
                    // 入口已被改写但状态文件没写 HOOK=installed：可能是别的工具/旧构建留下的补丁。
                    // 再补一次会把 E9 的跳转目标算错，所以失败关闭。
                    report = "gameui 入口已是 E9 跳转补丁，但状态文件未显示 Hook=installed（可能是旧构建残留）。为避免二次改写已拒绝注入，请重启游戏后再试。";
                    return false;
                }
                string err;
                if (!EnsureAssets(out err)) { report = err; return false; }
                // P0-4：每次新注入轮换会话 token —— 旧状态文件/旧命名事件立即失效，注入后必须由新 Hook 重写状态。
                var tok = RotateSessionToken(out err);
                if (tok.Length != 32) { report = err; return false; }
                bool changed;
                if (!ApplyIni(out changed, out err)) { report = err; return false; }

                var h = OpenProcess(ProcessCreateThread | ProcessQueryInformation | ProcessVmOperation |
                                    ProcessVmWrite | ProcessVmRead | ProcessSynchronize, false, v.Pid);
                if (h == IntPtr.Zero) { report = "OpenProcess 失败: " + Marshal.GetLastWin32Error(); return false; }
                IntPtr remoteDll = IntPtr.Zero;
                bool remoteThreadUnsafe = false;   // 远程线程超时仍在跑：此时不能 VirtualFreeEx（线程还在用参数内存）
                try
                {
                    bool loaded = v.DllLoaded;
                    if (!loaded)
                    {
                        var pathBytes = Encoding.Unicode.GetBytes(DllPath + "\0");
                        remoteDll = VirtualAllocEx(h, IntPtr.Zero, (IntPtr)pathBytes.Length, MemCommit | MemReserve, PageReadWrite);
                        if (remoteDll == IntPtr.Zero) { report = "VirtualAllocEx 失败: " + Marshal.GetLastWin32Error(); return false; }
                        IntPtr written;
                        if (!WriteProcessMemory(h, remoteDll, pathBytes, pathBytes.Length, out written))
                        {
                            report = "WriteProcessMemory 失败: " + Marshal.GetLastWin32Error();
                            return false;
                        }
                        var loadLibrary = GetProcAddress(GetModuleHandleA("kernel32.dll"), "LoadLibraryW");
                        if (loadLibrary == IntPtr.Zero) { report = "取不到 LoadLibraryW"; return false; }
                        lines.Add("远程 LoadLibraryW(" + DllPath + ") ...");
                        uint exitCode;
                        bool stillRunning;
                        if (!RunRemoteThread(h, loadLibrary, remoteDll, 30000, out exitCode, out stillRunning))
                        {
                            if (stillRunning)
                            {
                                remoteThreadUnsafe = true;
                                MarkPendingTaint(v.Pid, "远程 LoadLibraryW 超时且线程仍在运行（参数内存未回收）");
                                report = "远程 LoadLibraryW 超时且线程仍在运行：已标记该游戏进程为待重启（不再自动注入）";
                            }
                            else report = "远程 LoadLibraryW 超时/失败";
                            return false;
                        }
                        if (exitCode == 0)
                        {
                            report = "远程 LoadLibraryW 返回 0（DLL 没有加载成功，可能被安全软件阻止）";
                            return false;
                        }
                        lines.Add("DLL 已加载，HMODULE=0x" + exitCode.ToString("X8"));

                        // 模块表确认
                        var mod = FindModule(v.Pid, DllFileName);
                        if (mod == null)
                        {
                            report = "模块表里没有 " + DllFileName + "（LoadLibrary 可能被重定向）";
                            return false;
                        }
                        lines.Add("模块已枚举: base=" + Hex(mod.Base) + " path=" + mod.Path);
                        loaded = true;
                    }
                    else
                    {
                        lines.Add("DLL 已在目标进程内（上次 stop 后未卸载），直接重新安装 Hook。");
                    }

                    int startRva;
                    string perr;
                    if (!TryGetExportRva(DllPath, "SSF_Start", out startRva, out perr))
                    {
                        report = "解析内嵌 DLL 导出失败: " + perr;
                        return false;
                    }
                    var modNow = FindModule(v.Pid, DllFileName);
                    if (modNow == null) { report = "注入后找不到 DLL 模块"; return false; }
                    var startAddr = IntPtr.Add(modNow.Base, startRva);
                    lines.Add("调用 SSF_Start @" + Hex(startAddr) + " ...");
                    uint rc;
                    bool startStillRunning;
                    if (!RunRemoteThread(h, startAddr, IntPtr.Zero, 60000, out rc, out startStillRunning))
                    {
                        if (startStillRunning)
                        {
                            MarkPendingTaint(v.Pid, "远程 SSF_Start 超时且线程仍在运行");
                            report = "远程 SSF_Start 超时且线程仍在运行：已标记该游戏进程为待重启（不再自动注入）";
                        }
                        else report = "远程 SSF_Start 超时";
                        return false;
                    }
                    lines.Add("SSF_Start 返回 " + rc);

                    string statusResult = "", statusErr = "";
                    for (int i = 0; i < 20; i++)
                    {
                        var st = ReadStatusFile(v.Pid);
                        if (st.TryGetValue("RESULT", out statusResult)) { st.TryGetValue("ERROR", out statusErr); break; }
                        Thread.Sleep(100);
                    }
                    lines.Add("status: RESULT=" + (statusResult.Length > 0 ? statusResult : "(无)") +
                              (statusErr.Length > 0 ? " ERROR=" + statusErr : ""));
                    lines.Add("日志: " + LogPathOf(v.Pid));
                    lines.Add("status 文件: " + StatusPathOf(v.Pid));

                    bool ok = string.Equals(statusResult, "OK_FILTER", StringComparison.OrdinalIgnoreCase) ||
                              string.Equals(statusResult, "OK_DIAG", StringComparison.OrdinalIgnoreCase);
                    if (!ok)
                    {
                        // P0-2：状态不是 OK 时，先确认入口字节是否被改；改过就发 STOP 并核对回滚，失败则标记待重启。
                        string detail;
                        if (RecoverHook(v.Pid, out detail))
                        {
                            lines.Add("回滚核对: " + detail);
                        }
                        else
                        {
                            MarkPendingTaint(v.Pid, "注入失败且 Hook 回滚无法确认: " + detail);
                            lines.Add("回滚核对失败，已标记该游戏进程为待重启（不再自动注入）: " + detail);
                        }
                        report = "注入后状态不是 OK（" + (statusResult.Length > 0 ? statusResult : "无 status") + "）：" +
                                 (statusErr.Length > 0 ? statusErr : "见上面的日志") + "\n" + string.Join("\n", lines.ToArray());
                        return false;
                    }

                    // 恢复持久化的 passthrough 开关
                    if (PassThroughEnabled) SetEventHandle(EvPassKind, true);
                    ClearPendingTaint(v.Pid);
                    report = "注入成功（pid=" + v.Pid + "，模式 " + (FilterMode ? "filter" : "diag") + "）\n" +
                             string.Join("\n", lines.ToArray());
                    WriteLastStatus("injected pid=" + v.Pid + " mode=" + (FilterMode ? "filter" : "diag"));
                    return true;
                }
                finally
                {
                    if (remoteDll != IntPtr.Zero && !remoteThreadUnsafe)
                        VirtualFreeEx(h, remoteDll, IntPtr.Zero, MemRelease);
                    CloseHandle(h);
                }
            }
            catch (Exception ex)
            {
                report = ex.Message;
                return false;
            }
        }

        private static bool RunRemoteThread(IntPtr hProcess, IntPtr start, IntPtr param, uint timeoutMs,
                                            out uint exitCode, out bool stillRunning)
        {
            exitCode = 0;
            stillRunning = false;
            int tid;
            var th = CreateRemoteThread(hProcess, IntPtr.Zero, IntPtr.Zero, start, param, 0, out tid);
            if (th == IntPtr.Zero) return false;
            try
            {
                if (WaitForSingleObject(th, timeoutMs) != 0)
                {
                    // P0-2：超时后必须确认线程真的结束，不能直接回收参数内存
                    if (WaitForSingleObject(th, 5000) != 0) { stillRunning = true; return false; }
                }
                return GetExitCodeThread(th, out exitCode);
            }
            finally { CloseHandle(th); }
        }

        /// <summary>注入失败后的回滚核对：发 STOP，确认入口字节恢复原始 prologue。</summary>
        private static bool RecoverHook(int pid, out string detail)
        {
            detail = "";
            try
            {
                SetEventHandle(EvStopKind, true);
                for (int i = 0; i < 30; i++)
                {
                    Thread.Sleep(100);
                    var st = ReadStatusFile(pid);
                    string res;
                    if (st.TryGetValue("RESULT", out res) && string.Equals(res, "STOPPED", StringComparison.OrdinalIgnoreCase))
                    {
                        detail = "已确认 STOPPED";
                        break;
                    }
                }
            }
            catch (Exception ex) { detail = "发送停止信号失败: " + ex.Message; }
            try
            {
                var mod = FindModule(pid, GameUiFile);
                if (mod == null) { detail += "；找不到 gameui 模块"; return false; }
                var h = OpenProcess(ProcessVmRead | ProcessQueryInformation, false, pid);
                if (h == IntPtr.Zero) { detail += "；OpenProcess 失败"; return false; }
                try
                {
                    var b = ReadBytes(h, IntPtr.Add(mod.Base, TargetRva), PrologueLength);
                    bool restored = b != null && b.SequenceEqual(ExpectedPrologue);
                    detail += restored ? "；入口字节已恢复原始值" : "；入口字节仍不是原始值";
                    return restored;
                }
                finally { CloseHandle(h); }
            }
            catch (Exception ex) { detail += "；核对入口字节异常 " + ex.Message; return false; }
        }

        internal static bool StopHook(out string report)
        {
            report = "";
            var p = FindGameProcess();
            if (p == null) { report = "游戏没在运行，无需停止。"; return true; }
            int pid = p.Id;
            if (!HookInstalled(pid))
            {
                report = "当前没有已安装的 Hook（pid=" + pid + "）。";
                return true;
            }
            if (!SetEventHandle(EvStopKind, true)) { report = "打不开停止事件（可能 DLL 不是本工具注入的？）"; return false; }
            for (int i = 0; i < 50; i++)
            {
                Thread.Sleep(100);
                var st = ReadStatusFile(pid);
                string res;
                if (st.TryGetValue("RESULT", out res) && string.Equals(res, "STOPPED", StringComparison.OrdinalIgnoreCase))
                {
                    report = "已停止过滤并恢复 gameui.dll 原始入口字节（pid=" + pid + "）。DLL 仍驻留但不再拦截；重启游戏后自动重新注入。";
                    WriteLastStatus("stopped pid=" + pid);
                    return true;
                }
            }
            report = "已发送停止信号，但 5 秒内没看到 STOPPED 状态（详见 " + StatusPathOf(pid) + "）。";
            return false;
        }

        internal static bool ReloadConfig(out string report)
        {
            report = "";
            string err;
            bool changed;
            if (!ApplyIni(out changed, out err)) { report = "重建规则失败: " + err; return false; }
            var lines = new List<string>();
            lines.Add("ini: " + IniPath + (changed ? "（已更新）" : "（无变化）"));
            lines.Add("模式: " + (FilterMode ? "filter（真正删行）" : "diag（只记录，不删行）"));
            lines.Add("重复名称过滤: " + (DedupeEnabled ? "on（每一遍重建中，同名或仅末尾 #编号不同只保留第一条）" : "off（同名全部保留）"));
            var p = FindGameProcess();
            if (p == null)
            {
                lines.Add("游戏没在运行：规则已写盘，下次启动/注入时生效。");
                report = string.Join("\n", lines.ToArray());
                return true;
            }
            if (!HookInstalled(p.Id))
            {
                lines.Add("pid=" + p.Id + " 尚未安装 Hook：规则已写盘，注入后生效。");
                report = string.Join("\n", lines.ToArray());
                return true;
            }
            long before = 0;
            try { var fi = new FileInfo(LogPathOf(p.Id)); if (fi.Exists) before = fi.Length; } catch { }
            if (!SetEventHandle(EvReloadKind, true)) { report = "打不开 reload 事件"; return false; }
            Thread.Sleep(400);
            var tail = ReadTail(LogPathOf(p.Id), 200, before);
            var reloadLine = "";
            for (int i = tail.Count - 1; i >= 0; i--)
                if (tail[i].IndexOf("RELOAD config:", StringComparison.Ordinal) >= 0) { reloadLine = tail[i].Trim(); break; }
            lines.Add("已让 pid=" + p.Id + " 重读配置" + (reloadLine.Length > 0 ? "：" + reloadLine : "（未在日志里找到 RELOAD 行）"));
            report = string.Join("\n", lines.ToArray());
            WriteLastStatus("reload pid=" + p.Id + " changed=" + changed);
            return true;
        }

        private static List<string> ReadTail(string path, int maxLines, long afterOffset)
        {
            var lines = new List<string>();
            try
            {
                if (!File.Exists(path)) return lines;
                using (var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite))
                {
                    if (afterOffset > 0 && afterOffset <= fs.Length) fs.Seek(afterOffset, SeekOrigin.Begin);
                    using (var sr = new StreamReader(fs, Encoding.UTF8))
                    {
                        string line;
                        while ((line = sr.ReadLine()) != null)
                        {
                            lines.Add(line);
                            if (lines.Count > maxLines) lines.RemoveAt(0);
                        }
                    }
                }
            }
            catch { }
            return lines;
        }

        internal static bool SetPassThrough(bool on, out string report)
        {
            Config.Set(ConfigKeyPass, on ? "on" : "off");
            var p = FindGameProcess();
            if (p == null || !HookInstalled(p.Id))
            {
                report = "已记录 passthrough=" + (on ? "on" : "off") + "（游戏未注入，下次注入时自动套用）。";
                return true;
            }
            bool ok = SetEventHandle(EvPassKind, on);
            report = ok
                ? ("已" + (on ? "开启" : "关闭") + " passthrough（pid=" + p.Id + "）：" +
                   (on ? "匹配行会恢复显示（临时对比用）" : "匹配行重新被过滤"))
                : "操作 passthrough 事件失败（DLL 可能不是本工具注入的）";
            return ok;
        }

        /// <summary>开关「组服列表重复名称过滤」：写 config.ini + 重建 ini；已注入时立即 reload。</summary>
        internal static bool SetDedupe(bool on, out string report)
        {
            report = "";
            try
            {
                Config.Set(ConfigKeyDedupe, on ? "on" : "off");
                string err;
                bool changed;
                if (!EnsureAssets(out err)) { report = "解包失败：" + err; return false; }
                if (!ApplyIni(out changed, out err)) { report = "重建 ini 失败：" + err; return false; }
                var p = FindGameProcess();
                bool hooked = p != null && HookInstalled(p.Id);
                bool reloaded = false;
                if (hooked && changed) reloaded = SetEventHandle(EvReloadKind, true);
                report = "重复名称过滤：" + (on ? "已开启（每一遍重建中，同名或仅末尾 #编号不同只保留第一条）" : "已关闭（同名服务器全部保留）")
                       + "（" + (changed ? "ini 已更新" : "ini 无变化")
                       + (hooked
                            ? "；已注入的游戏进程" + (changed
                                ? (reloaded ? "已触发 reload" : "reload 信号发送失败，可稍后运行 --group-filter reload")
                                : "无需 reload")
                            : "；游戏未注入，下次注入时生效")
                       + "）。";
                return true;
            }
            catch (Exception ex) { report = "切换重复名称过滤失败：" + ex.Message; return false; }
        }

        private static bool SetEventHandle(string kind, bool set)
        {
            var name = EventName(kind);
            if (name.Length == 0) return false;
            var h = OpenEventW(EventModifyState, false, name);
            if (h == IntPtr.Zero) return false;
            try
            {
                if (set) return SetEvent(h);
                return ResetEvent(h);
            }
            finally { CloseHandle(h); }
        }

        // ================================================================ 独立监视进程（组服过滤层，默认常开）
        /// <summary>托盘/界面状态行用：组服过滤当前是否已挂载（不抛异常）。</summary>
        internal static string StateText()
        {
            try
            {
                if (!AutoEnabled) return "组服关";
                var p = FindGameProcess();
                if (p != null && HookInstalled(p.Id)) return "组服已挂";
                if (!ResidentRunning()) return "组服监视未运行";
                return "组服待游戏";
            }
            catch { }
            return "组服待游戏";
        }

        /// <summary>独立监视进程是否在跑（命名互斥体；不按进程名判断，避免误伤同名程序）。</summary>
        internal static bool ResidentRunning()
        {
            try
            {
                Mutex m;
                if (!Mutex.TryOpenExisting(ResidentMutexName, out m)) return false;
                m.Dispose();
                return true;
            }
            catch { return false; }
        }

        /// <summary>监视进程 PID（读 groupfilter\resident.pid；拿不到返回 0）。</summary>
        internal static int ResidentProcessId()
        {
            try
            {
                if (!File.Exists(ResidentPidPath)) return 0;
                int pid;
                return int.TryParse(SafeFile.Read(ResidentPidPath).Trim(), out pid) && pid > 0 ? pid : 0;
            }
            catch { return 0; }
        }

        /// <summary>启动独立监视进程（自带互斥体，重复调用无害）。</summary>
        internal static bool StartResident(out string report)
        {
            report = "";
            if (ResidentRunning())
            {
                int pid = ResidentProcessId();
                report = "组服过滤监视进程已在运行" + (pid > 0 ? "（PID " + pid + "）" : "") + "。";
                return true;
            }
            try
            {
                var exe = Path.Combine(IpEngine.Root, "FilterTool.exe");
                if (!File.Exists(exe)) { report = "找不到 " + exe + "。"; return false; }
                Process.Start(new ProcessStartInfo(exe, "--group-filter resident")
                {
                    UseShellExecute = false,
                    CreateNoWindow = true,
                    WorkingDirectory = IpEngine.Root
                });
                for (int i = 0; i < 40; i++)
                {
                    Thread.Sleep(150);
                    if (ResidentRunning())
                    {
                        int pid = ResidentProcessId();
                        report = "已启动组服过滤监视进程" + (pid > 0 ? "（PID " + pid + "）" : "") + "。";
                        return true;
                    }
                }
                report = "监视进程启动超时：6 秒内没看到互斥体 " + ResidentMutexName + "。";
                return false;
            }
            catch (Exception ex) { report = "启动监视进程失败：" + ex.Message; return false; }
        }

        /// <summary>停止独立监视进程（按 pid 文件结束；不按进程名乱杀）。</summary>
        internal static bool StopResident(out string report)
        {
            report = "";
            int pid = ResidentProcessId();
            bool running = ResidentRunning();
            if (!running && pid == 0) { report = "组服过滤监视进程未在运行。"; return true; }
            if (pid > 0 && pid == Process.GetCurrentProcess().Id) { report = "当前进程就是监视进程，忽略。"; return true; }
            if (pid <= 0)
            {
                report = "监视进程在运行但读不到 pid 文件（" + ResidentPidPath + "），请手动结束。";
                return false;
            }
            if (!running)
            {
                // 互斥体已经没了：pid 文件是上次进程被强杀留下的，直接清理，不去 Kill 可能已被复用的 PID
                try { File.Delete(ResidentPidPath); } catch { }
                report = "组服过滤监视进程未在运行（已清理残留 pid 文件）。";
                return true;
            }
            try { Process.GetProcessById(pid).Kill(); }
            catch (Exception ex) { report = "结束监视进程失败：" + ex.Message; return false; }
            for (int i = 0; i < 30; i++)
            {
                Thread.Sleep(100);
                if (!ResidentRunning()) { report = "已停止组服过滤监视进程（PID " + pid + "）。"; return true; }
            }
            report = "已结束监视进程 PID " + pid + "，但互斥体仍在（可能正在退出）。";
            return false;
        }

        /// <summary>auto on 时确保监视进程在跑；auto off 时什么都不做。</summary>
        internal static bool EnsureResident(out string report)
        {
            report = "";
            if (!AutoEnabled) { report = "组服列表过滤已关闭（auto off），不启动监视进程。"; return true; }
            return StartResident(out report);
        }

        /// <summary>CLI/内部：开启或关闭整层（auto 配置 + 监视进程 + 已注入的游戏 hook）。默认常开，off 仅排障用。</summary>
        internal static bool SetEnabled(bool on, out string report)
        {
            report = "";
            try
            {
                Config.Set(ConfigKeyAuto, on ? "on" : "off");
                var lines = new List<string>();
                lines.Add(on ? "组服列表过滤：已开启（只删匹配的列表行，不影响名字层）" : "组服列表过滤：已关闭");
                string err;
                if (on)
                {
                    bool changed;
                    if (!EnsureAssets(out err)) { report = "解包失败：" + err; return false; }
                    if (!ApplyIni(out changed, out err)) { report = "生成 ini 失败：" + err; return false; }
                    string r;
                    StartResident(out r);
                    lines.Add(r);
                    var p = FindGameProcess();
                    if (p == null) lines.Add("游戏没在运行：监视进程会在游戏启动后自动注入。");
                    else if (HookInstalled(p.Id)) lines.Add("游戏已在过滤中（pid=" + p.Id + "）。");
                    else if (InjectNow(out r)) lines.Add(r);
                    else lines.Add("暂未注入：" + r + "\r\n（监视进程会在游戏启动/加载 gameui 后自动注入）");
                }
                else
                {
                    string r;
                    StopHook(out r);
                    lines.Add(r);
                    StopResident(out r);
                    lines.Add(r);
                }
                report = string.Join("\r\n", lines.ToArray());
                return true;
            }
            catch (Exception ex) { report = "切换组服过滤失败：" + ex.Message; return false; }
        }

        /// <summary>独立监视进程主体：持有命名互斥体，每秒 tick；auto 变 off 后自行退出。</summary>
        internal static int RunResident(Action<string> write)
        {
            if (write == null) write = Console.WriteLine;
            bool created;
            using (var mutex = new Mutex(true, ResidentMutexName, out created))
            {
                if (!created)
                {
                    write("组服过滤监视进程已在运行（互斥体 " + ResidentMutexName + " 已被占用）。");
                    return 0;
                }
                _residentMode = true;
                try
                {
                    Directory.CreateDirectory(Dir);
                    SafeFile.Write(ResidentPidPath, Process.GetCurrentProcess().Id.ToString());
                    write("组服过滤监视进程已启动（PID " + Process.GetCurrentProcess().Id + "）：auto off 时自动退出。");
                    WriteLastStatus("resident started");
                    int ticks = 0;
                    int offStreak = 0;
                    while (true)
                    {
                        // 配置读失败或瞬时读不到 auto 键时不要直接退出：需要连续约 12 秒确认关闭。
                        bool autoNow;
                        try { autoNow = AutoEnabled; } catch { autoNow = true; }
                        if (!autoNow)
                        {
                            if (++offStreak >= 12) { WriteLastStatus("resident stopped: auto off"); break; }
                        }
                        else offStreak = 0;
                        TickCoreSafe();
                        ticks++;
                        if (ticks % 30 == 0) WriteLastStatus("resident running");
                        Thread.Sleep(1000);
                    }
                    return 0;
                }
                finally
                {
                    try { File.Delete(ResidentPidPath); } catch { }
                    try { mutex.ReleaseMutex(); } catch { }
                }
            }
        }

        /// <summary>单飞 tick（异常只写状态，不把监视进程带崩）。</summary>
        private static void TickCoreSafe()
        {
            if (Interlocked.CompareExchange(ref _tickBusy, 1, 0) != 0) return;
            try { TickCore(); }
            catch (Exception ex) { WriteLastStatus("tick error: " + ex.Message); }
            finally { Interlocked.Exchange(ref _tickBusy, 0); }
        }

        private static void TickCore()
        {
            string err;
            bool changed;
            // 规则/模式变化 → 重建 ini；已注入时顺便 reload
            var rulesStamp = RulesStamp();
            if (rulesStamp != _lastRulesStamp)
            {
                _lastRulesStamp = rulesStamp;
                if (ApplyIni(out changed, out err) && changed)
                {
                    var p0 = FindGameProcess();
                    if (p0 != null && HookInstalled(p0.Id)) SetEventHandle(EvReloadKind, true);
                }
            }
            else if (_lastRulesStamp == DateTime.MinValue)
            {
                ApplyIni(out changed, out err);
                _lastRulesStamp = RulesStamp();
            }

            var p = FindGameProcess();
            if (p == null)
            {
                if (_lastKnownPid != 0)
                {
                    ClearPendingTaint(_lastKnownPid);   // P0-2：游戏退出即清掉待重启标记
                    _lastKnownPid = 0;
                    _lastPid = 0;
                    WriteLastStatus("game exited; waiting for next start");
                }
                return;
            }
            int pid = p.Id;
            if (pid != _lastPid)
            {
                _lastPid = pid;
                _lastKnownPid = pid;
                _lastAttempt = DateTime.MinValue;
                _lastInjectError = "";
                WriteLastStatus("detected game pid=" + pid + " (auto=" + AutoEnabled + " mode=" + (FilterMode ? "filter" : "diag") + ")");
                Console.WriteLine("组服过滤：检测到游戏 pid=" + pid + "，准备自动注入。");
            }

            if (HookInstalled(pid)) return;
            if (HasPendingTaint(pid))
            {
                if (_lastInjectError != "pending-taint")
                {
                    _lastInjectError = "pending-taint";
                    Console.WriteLine("组服过滤：pid=" + pid + " 上次注入异常且回滚未确认，等游戏重启后再自动注入。");
                    WriteLastStatus("auto-inject paused pid=" + pid + ": pending taint (" + PendingPathOf(pid) + ")");
                }
                return;
            }
            var dllMod = FindModule(pid, DllFileName);
            if (dllMod != null)
            {
                // DLL 在但 hook 不在：可能是用户手动 --group-filter stop，尊重该状态，等游戏重启
                return;
            }
            if (DateTime.Now - _lastAttempt < TimeSpan.FromSeconds(10)) return;
            _lastAttempt = DateTime.Now;
            if (FindModule(pid, GameUiFile) == null) return;   // gameui 还没加载

            string report;
            if (InjectNow(out report))
            {
                Console.WriteLine("组服过滤：自动注入成功（pid=" + pid + "）");
                WriteLastStatus("auto-injected pid=" + pid);
            }
            else
            {
                if (!string.Equals(report, _lastInjectError, StringComparison.Ordinal))
                {
                    _lastInjectError = report;
                    Console.WriteLine("组服过滤：自动注入失败 —— " + FirstLine(report));
                    WriteLastStatus("auto-inject failed pid=" + pid + ": " + FirstLine(report));
                }
            }
        }

        private static DateTime RulesStamp()
        {
            try
            {
                var newest = DateTime.MinValue;
                AddStamp(ref newest, RulesPath);                                 // rules-profiles\custom.txt：唯一规则文件
                AddStamp(ref newest, SteamServerFilterRules.Engine.RulesFile);   // block_rules.txt：名字层重新生成
                AddStamp(ref newest, Config.File);                               // config.ini：namelayer/mode 等设置
                return newest;
            }
            catch { return DateTime.MinValue; }
        }

        private static void AddStamp(ref DateTime newest, string path)
        {
            try
            {
                if (string.IsNullOrEmpty(path) || !File.Exists(path)) return;
                var t = File.GetLastWriteTime(path);
                if (t > newest) newest = t;
            }
            catch { }
        }

        /// <summary>统一规则的一行摘要（给 status/rules 用）：生效/并入/跳过条数。</summary>
        internal static string NameLayerSummary()
        {
            var sb = new StringBuilder();
            sb.Append("名字层合并: ").Append(NameLayerModeText());
            sb.Append("；生效 ").Append(_lastNameLayerTotal).Append(" 条，并入 ")
              .Append(_lastNameLayerMerged).Append(" 条");
            if (_lastNameLayerSkipped > 0) sb.Append("，跳过 ").Append(_lastNameLayerSkipped).Append(" 条");
            return sb.ToString();
        }

        private static string FirstLine(string s)
        {
            if (string.IsNullOrEmpty(s)) return "";
            var i = s.IndexOf('\n');
            return i < 0 ? s : s.Substring(0, i);
        }

        internal static void WriteLastStatus(string message)
        {
            try
            {
                Directory.CreateDirectory(Dir);
                SafeFile.Write(_residentMode ? ResidentStatusPath : LastStatusPath,
                    "TIME=" + DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss") + "\r\n" +
                    "PID=" + _lastKnownPid + "\r\n" +
                    "AUTO=" + (AutoEnabled ? "on" : "off") + "\r\n" +
                    "MODE=" + (FilterMode ? "filter" : "diag") + "\r\n" +
                    "MESSAGE=" + (message ?? "") + "\r\n");
            }
            catch { }
        }

        // ================================================================ 命令行
        internal static int Run(string[] rest, Action<string> write)
        {
            if (write == null) write = Console.WriteLine;
            var sub = (rest.Length >= 1 ? rest[0] : "status").Trim().ToLowerInvariant();
            if (sub == "help" || sub == "-h" || sub == "--help") { write(HelpText()); return 0; }
            if (sub == "status" || sub == "") return CmdStatus(write);
            if (sub == "rules") return CmdRules(write);
            if (sub == "init" || sub == "extract") return CmdInit(write);
            if (sub == "verify") return CmdVerify(write);
            if (sub == "inject") return CmdInject(write);
            if (sub == "stop") return CmdStop(write);
            if (sub == "reload" || sub == "rules-reload") return CmdReload(write);
            if (sub == "passthrough" || sub == "pass") return CmdPassThrough(rest, write);
            if (sub == "auto") return CmdAuto(rest, write);
            if (sub == "mode") return CmdMode(rest, write);
            if (sub == "dedupe" || sub == "dedup" || sub == "unique") return CmdDedupe(rest, write);
            if (sub == "namelayer" || sub == "name-layer" || sub == "merge") return CmdNameLayer(rest, write);
            if (sub == "watch") return CmdWatch(rest, write);
            if (sub == "resident") return RunResident(write);
            write("未知子命令: " + sub);
            write(HelpText());
            return 2;
        }

        internal static string HelpText()
        {
            var sb = new StringBuilder();
            sb.AppendLine("组服列表过滤（Steam 组战役模式服务器列表里按服名删行）：");
            sb.AppendLine("  FilterTool.exe --group-filter                 状态（进程/指纹/Hook/规则/日志路径）");
            sb.AppendLine("  FilterTool.exe --group-filter init            解包内嵌 DLL 并生成 ini（不注入）");
            sb.AppendLine("  FilterTool.exe --group-filter verify          只读门禁：进程 + gameui 指纹 + 远端模块/字节/虚表");
            sb.AppendLine("  FilterTool.exe --group-filter inject          立即注入（游戏已启动且已加载 gameui.dll）");
            sb.AppendLine("  FilterTool.exe --group-filter stop            停止过滤并恢复原始 9 字节（DLL 驻留不卸载）");
            sb.AppendLine("  FilterTool.exe --group-filter reload          按规则文件重建 ini，并让已注入的进程重读");
            sb.AppendLine("  FilterTool.exe --group-filter rules           显示规则文件、路径和生成的正则");
            sb.AppendLine("  FilterTool.exe --group-filter passthrough on|off  临时放行匹配行（前后对比用）");
            sb.AppendLine("  FilterTool.exe --group-filter auto on|off     独立层总开关（默认 on=常开）；off 仅供排障，--run 不会自动拉起");
            sb.AppendLine("  FilterTool.exe --group-filter resident       只跑独立监视进程（常开时由 --run 自动拉起；auto off 自动退出）");
            sb.AppendLine("  FilterTool.exe --group-filter mode filter|diag  filter=真正删行；diag=只记录不删行");
            sb.AppendLine("  FilterTool.exe --group-filter dedupe on|off    重复名称过滤：每一遍重建中，同名或仅末尾 #编号不同只保留第一条（默认 on）");
            sb.AppendLine("  FilterTool.exe --group-filter namelayer [off|custom|all]  兼容旧参数（规则已统一，不再影响结果）");
            sb.AppendLine("  FilterTool.exe --group-filter watch [秒数]    只跑自动注入监视循环（不开 WinDivert，用于验证）");
            sb.AppendLine("  统一规则文件：rules-profiles\\custom.txt（UTF-8，一行一条；名字层丢包与组服列表删行共用；# 开头是注释）");
            return sb.ToString();
        }

        private static string ModeText()
        {
            return FilterMode ? "filter（真正删行）" : "diag（只记录，不删行）";
        }

        private static int CmdStatus(Action<string> write)
        {
            write("=== 组服列表过滤（GroupServerFilter）===");
            write("自动注入: " + (AutoEnabled ? "on（常开：独立监视进程在游戏启动后自动注入）" : "off（已用 --group-filter auto off 临时关闭；--run 不会自动拉起）"));
            write("监视进程: " + (ResidentRunning() ? "运行中 · PID " + ResidentProcessId() : "未运行") + " · 状态文件 " + ResidentStatusPath);
            write("模式: " + ModeText());
            write("passthrough: " + (PassThroughEnabled ? "on（临时放行）" : "off"));
            write("重复名称过滤: " + (DedupeEnabled
                ? "on（每一遍重建中，同名或仅末尾 #编号不同只保留第一条；可用 --group-filter dedupe off 关闭）"
                : "off（同名服务器全部保留）"));
            write("统一规则文件: " + RulesPath + "（名字层丢包 + 组服列表删行共用）");
            string regex, err;
            if (BuildRegex(out regex, out err))
                write("生成正则: " + (regex.Length == 0 ? "(空规则：不拦任何行)" : regex));
            else write("生成正则失败: " + err);
            write(NameLayerSummary());
            for (int i = 0; i < _lastNameLayerSkipReasons.Count && i < 5; i++)
                write("  规则跳过: " + _lastNameLayerSkipReasons[i]);
            write("内嵌 DLL: " + DllPath + (File.Exists(DllPath) ? "（已解包 " + new FileInfo(DllPath).Length + " 字节）" : "（尚未解包）"));
            write("ini: " + IniPath);
            write("最后动作: " + LastStatusPath);

            var p = FindGameProcess();
            if (p == null)
            {
                write("游戏进程: 未运行");
                return 0;
            }
            var st = ReadStatusFile(p.Id);
            string res, mode, target, tramp, sha, hook;
            st.TryGetValue("RESULT", out res); st.TryGetValue("MODE", out mode);
            st.TryGetValue("TARGET_ADDR", out target); st.TryGetValue("HOOK", out hook);
            st.TryGetValue("TRAMPOLINE", out tramp); st.TryGetValue("SHA256_OK", out sha);
            write("游戏进程: pid=" + p.Id);
            write("  状态: " + (res ?? "(无 status)") + " · MODE=" + (mode ?? "-") + " · HOOK=" + (hook ?? "-"));
            write("  TARGET_ADDR=" + (target ?? "-") + " TRAMPOLINE=" + (tramp ?? "-") + " SHA256_OK=" + (sha ?? "-"));
            string dedupe;
            st.TryGetValue("DEDUPE", out dedupe);
            if (!string.IsNullOrEmpty(dedupe))
                write("  重复过滤: " + (dedupe == "1" ? "on" : "off") + "（DLL 已读取的配置）");
            write("  日志: " + LogPathOf(p.Id));
            write("  status: " + StatusPathOf(p.Id));
            return 0;
        }

        private static int CmdRules(Action<string> write)
        {
            string err;
            bool ignored;
            if (!EnsureAssets(out err)) { write("准备资源失败: " + err); return 1; }
            ApplyIni(out ignored, out err);
            write("统一规则文件: " + RulesPath + "（名字层丢包 + 组服列表删行共用）");
            var text = File.Exists(RulesPath) ? SafeFile.Read(RulesPath) : "";
            foreach (var line in text.Replace("\r\n", "\n").Split('\n')) write("  " + line);
            string regex;
            if (!BuildRegex(out regex, out err)) { write("生成正则失败: " + err); return 1; }
            write("生成正则: " + (regex.Length == 0 ? "(空规则：不拦任何行)" : regex));
            write(NameLayerSummary());
            for (int i = 0; i < _lastNameLayerSkipReasons.Count && i < 10; i++)
                write("规则跳过: " + _lastNameLayerSkipReasons[i]);
            write("DLL ini: " + IniPath);
            return 0;
        }

        private static int CmdInit(Action<string> write)
        {
            string err;
            bool changed;
            if (!EnsureAssets(out err)) { write("解包失败: " + err); return 1; }
            if (!ApplyIni(out changed, out err)) { write("生成 ini 失败: " + err); return 1; }
            write("内嵌 DLL: " + DllPath + "（" + new FileInfo(DllPath).Length + " 字节）");
            write("统一规则文件: " + RulesPath);
            write("ini: " + IniPath + (changed ? "（已更新）" : "（无变化）"));
            write("模式: " + ModeText());
            return 0;
        }

        private static int CmdVerify(Action<string> write)
        {
            var v = Verify(true);
            foreach (var l in v.Lines) write(l);
            if (v.Ok) { write("门禁结果: 全部通过（游戏版本在已验证列表里）。"); return 0; }
            write("门禁结果: 未通过 —— " + v.Error);
            return 1;
        }

        private static int CmdInject(Action<string> write)
        {
            string report;
            var ok = InjectNow(out report);
            foreach (var l in report.Replace("\r\n", "\n").Split('\n')) write(l);
            return ok ? 0 : 1;
        }

        private static int CmdStop(Action<string> write)
        {
            string report;
            var ok = StopHook(out report);
            write(report);
            return ok ? 0 : 1;
        }

        private static int CmdReload(Action<string> write)
        {
            string report;
            var ok = ReloadConfig(out report);
            foreach (var l in report.Replace("\r\n", "\n").Split('\n')) write(l);
            return ok ? 0 : 1;
        }

        private static int CmdPassThrough(string[] rest, Action<string> write)
        {
            if (rest.Length < 2)
            {
                write("用法: FilterTool.exe --group-filter passthrough on|off");
                return 2;
            }
            var v = rest[1].Trim().ToLowerInvariant();
            if (v != "on" && v != "off" && v != "1" && v != "0")
            {
                write("passthrough 只接受 on/off");
                return 2;
            }
            bool on = v == "on" || v == "1";
            string report;
            var ok = SetPassThrough(on, out report);
            write(report);
            return ok ? 0 : 1;
        }

        private static int CmdAuto(string[] rest, Action<string> write)
        {
            if (rest.Length < 2)
            {
                write("组服列表过滤（独立层）: " + (AutoEnabled ? "开启" : "关闭"));
                write("监视进程: " + (ResidentRunning() ? "运行中 · PID " + ResidentProcessId() : "未运行"));
                write("用法: FilterTool.exe --group-filter auto on|off");
                return 0;
            }
            var v = rest[1].Trim().ToLowerInvariant();
            if (v != "on" && v != "off")
            {
                write("auto 只接受 on/off");
                return 2;
            }
            string report;
            var ok = SetEnabled(v == "on", out report);
            foreach (var l in report.Replace("\r\n", "\n").Split('\n')) write(l);
            if (!ok) return 1;
            write("auto=" + v + " 已写入 config.ini（" + (v == "on" ? "常开" : "已临时关闭，仅排障用") + "）。");
            return 0;
        }

        private static int CmdMode(string[] rest, Action<string> write)
        {
            if (rest.Length < 2)
            {
                write("当前模式: " + ModeText());
                write("用法: FilterTool.exe --group-filter mode filter|diag");
                return 0;
            }
            var v = rest[1].Trim().ToLowerInvariant();
            if (v != "filter" && v != "diag")
            {
                write("mode 只接受 filter 或 diag");
                return 2;
            }
            Config.Set(ConfigKeyMode, v);
            string err;
            bool changed;
            if (!ApplyIni(out changed, out err)) { write("重建 ini 失败: " + err); return 1; }
            var p = FindGameProcess();
            if (p != null && HookInstalled(p.Id)) SetEventHandle(EvReloadKind, true);
            write("模式已设为 " + v + "（" + (changed ? "ini 已更新" : "ini 无变化") + "；已注入的进程已触发 reload）。");
            return 0;
        }

        private static int CmdDedupe(string[] rest, Action<string> write)
        {
            if (rest.Length < 2)
            {
                write("重复名称过滤: " + (DedupeEnabled ? "on（每一遍重建中，同名或仅末尾 #编号不同只保留第一条）" : "off（同名服务器全部保留）"));
                write("说明: 只比较同一遍列表重建内的显示名；忽略开头的 UTF-8 BOM 和末尾的 #编号（如 #90 / #85 视为同一台）；名字为空的行不参与去重。");
                write("用法: FilterTool.exe --group-filter dedupe on|off");
                return 0;
            }
            var v = rest[1].Trim().ToLowerInvariant();
            if (v != "on" && v != "off" && v != "1" && v != "0")
            {
                write("dedupe 只接受 on/off");
                return 2;
            }
            bool on = v == "on" || v == "1";
            string report;
            var ok = SetDedupe(on, out report);
            write(report);
            return ok ? 0 : 1;
        }

        private static int CmdNameLayer(string[] rest, Action<string> write)
        {
            if (rest.Length < 2)
            {
                string regex0, err0;
                BuildRegex(out regex0, out err0);
                write(NameLayerSummary());
                write("说明: 规则已统一到 rules-profiles\\custom.txt 一个文件，名字层丢包与组服列表删行天然共用；custom/all/off 仅为兼容旧参数，不再影响结果。");
                write("用法: FilterTool.exe --group-filter namelayer [custom]（旧值 off/all 仍接受）");
                return 0;
            }
            var v = rest[1].Trim().ToLowerInvariant();
            if (v == "on" || v == "1" || v == "true" || v == "yes") v = "all";
            if (v == "0" || v == "false" || v == "no" || v == "none") v = "off";
            if (v != "off" && v != "custom" && v != "all")
            {
                write("namelayer 只接受 off / custom / all");
                return 2;
            }
            Config.Set(ConfigKeyNameLayer, v);
            string err;
            bool changed;
            if (!ApplyIni(out changed, out err)) { write("重建 ini 失败: " + err); return 1; }
            var p = FindGameProcess();
            var hooked = p != null && HookInstalled(p.Id);
            if (hooked && changed) SetEventHandle(EvReloadKind, true);
            write("名字层合并已设为 " + v + "（兼容参数，规则已统一、不影响结果；" + (changed ? "ini 已更新" : "ini 无变化")
                  + (hooked ? "；已注入的进程 " + (changed ? "已触发 reload" : "无需 reload") : "") + "）。");
            string regex, err2;
            if (BuildRegex(out regex, out err2)) write(NameLayerSummary());
            else write("生成正则失败: " + err2);
            return 0;
        }

        private static int CmdWatch(string[] rest, Action<string> write)
        {
            int secs = 15;
            if (rest.Length >= 2) int.TryParse(rest[1], out secs);
            if (secs <= 0) secs = 15;
            write("组服过滤自动注入监视（" + secs + " 秒；不开 WinDivert）...");
            var deadline = DateTime.Now.AddSeconds(secs);
            int lastPid = 0;
            string lastState = "";
            while (DateTime.Now < deadline)
            {
                var p = FindGameProcess();
                string state;
                if (p == null) state = "游戏未运行";
                else
                {
                    var installed = HookInstalled(p.Id);
                    var dll = FindModule(p.Id, DllFileName) != null;
                    state = "pid=" + p.Id + " hook=" + (installed ? "installed" : "no") + " dll=" + (dll ? "loaded" : "no");
                    if (p.Id != lastPid) { lastPid = p.Id; write("检测到游戏 pid=" + p.Id); }
                    if (!installed && !dll)
                    {
                        var v = Verify(false);
                        if (!v.Ok) state += "（" + v.Error + "）";
                    }
                }
                if (state != lastState) { write("  " + state); lastState = state; }
                Thread.Sleep(1000);
            }
            write("监视结束。当前状态：");
            return CmdStatus(write);
        }

        // ================================================================ Win32
        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        private struct MODULEENTRY32W
        {
            public uint dwSize;
            public uint th32ModuleID;
            public uint th32ProcessID;
            public uint GlblcntUsage;
            public uint ProccntUsage;
            public IntPtr modBaseAddr;
            public uint modBaseSize;
            public IntPtr hModule;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 256)]
            public string szModule;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)]
            public string szExePath;
        }

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr OpenProcess(uint access, bool inherit, int pid);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool CloseHandle(IntPtr h);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool ReadProcessMemory(IntPtr hProcess, IntPtr addr, byte[] buffer, int size, out IntPtr read);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr addr, byte[] buffer, int size, out IntPtr written);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr addr, IntPtr size, uint allocType, uint protect);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool VirtualFreeEx(IntPtr hProcess, IntPtr addr, IntPtr size, uint freeType);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr sa, IntPtr stackSize,
                                                        IntPtr startAddress, IntPtr parameter, uint flags, out int threadId);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern uint WaitForSingleObject(IntPtr handle, uint milliseconds);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool GetExitCodeThread(IntPtr handle, out uint exitCode);

        [DllImport("kernel32.dll", CharSet = CharSet.Ansi, SetLastError = true)]
        private static extern IntPtr GetModuleHandleA(string moduleName);

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern IntPtr LoadLibraryW(string path);

        [DllImport("kernel32.dll", CharSet = CharSet.Ansi, SetLastError = true)]
        private static extern IntPtr GetProcAddress(IntPtr module, string procName);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr CreateToolhelp32Snapshot(uint flags, int pid);

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern bool Module32FirstW(IntPtr snapshot, ref MODULEENTRY32W entry);

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern bool Module32NextW(IntPtr snapshot, ref MODULEENTRY32W entry);

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern bool QueryFullProcessImageNameW(IntPtr hProcess, uint flags, StringBuilder name, ref int size);

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern IntPtr OpenEventW(uint access, bool inherit, string name);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool SetEvent(IntPtr handle);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool ResetEvent(IntPtr handle);
    }
}
