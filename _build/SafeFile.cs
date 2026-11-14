// ============================================================================
//  SafeFile —— 状态文件的安全读写（修复审计报告 V-05 / V-10）
//
//  背景：常驻进程、统一界面、独立界面会同时读写同一批状态文件
//        （ip_block.txt / pending_resolve.tsv / name_ip_links.tsv / name_ip_map.tsv /
//          rules-profiles\*.txt）。原来的"读整个文件 → 改内存 → 覆盖写"在并发下会：
//          · 后写的一方整体覆盖丢掉先写一方的更新；
//          · File.WriteAllText 非原子，对方可能读到写了一半的截断内容。
//
//  做法：
//    1. 所有写入走"临时文件 + 原子替换"（NTFS 上 File.Replace 是原子的）；
//    2. 读改写用跨进程命名互斥量串行化（Global\ 失败则退回本会话的 Local\）；
//    3. 统一提供写表/写规则前的输入清洗（去掉 \t \r \n，防止破坏 TSV / 规则文件格式）。
// ============================================================================

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;

namespace SteamServerFilterIpBlock
{
    internal static class SafeFile
    {
        private static readonly UTF8Encoding Utf8NoBom = new UTF8Encoding(false);
        private static Mutex _mutex;
        private static bool _mutexTried;

        /// <summary>跨进程互斥量：Global\ 需要权限，失败时退回 Local\（同会话内仍然有效）。</summary>
        private static Mutex Lock
        {
            get
            {
                if (_mutexTried) return _mutex;
                _mutexTried = true;
                foreach (var name in new[] { @"Global\SteamServerFilterStateV1", @"Local\SteamServerFilterStateV1" })
                {
                    try { _mutex = new Mutex(false, name); return _mutex; }
                    catch { }
                }
                return null;
            }
        }

        /// <summary>
        /// 在一把跨进程锁里执行读改写，避免并发丢更新。
        /// P1：锁不可用或等待超时一律失败关闭——宁可不写状态文件，也不要在无锁状态覆盖别人的写入。
        /// </summary>
        public static T WithLock<T>(Func<T> body)
        {
            var m = Lock;
            if (m == null)
                throw new InvalidOperationException("状态文件锁不可用（无法创建全局互斥体），已拒绝在无锁状态下读改写状态文件。");
            bool held = false;
            try { held = m.WaitOne(TimeSpan.FromSeconds(20)); }
            catch (AbandonedMutexException) { held = true; }
            if (!held)
                throw new InvalidOperationException("等待状态文件锁超时（20 秒），已拒绝在无锁状态下读改写状态文件。");
            try { return body(); }
            finally { if (held) { try { m.ReleaseMutex(); } catch { } } }
        }

        public static void WithLock(Action body)
        {
            WithLock<bool>(() => { body(); return true; });
        }

        /// <summary>
        /// 原子写入：临时文件 + File.Replace（目标不存在时 File.Move）。
        /// P1：不再退回非原子的 File.Copy——原子替换失败就让调用方看到异常并保留旧文件。
        /// </summary>
        public static void Write(string path, string text)
        {
            WithLock(() =>
            {
                var dir = Path.GetDirectoryName(path);
                if (!string.IsNullOrEmpty(dir) && !Directory.Exists(dir)) Directory.CreateDirectory(dir);
                var tmp = path + ".tmp" + Process.GetCurrentProcess().Id;
                File.WriteAllText(tmp, text, Utf8NoBom);
                try
                {
                    if (File.Exists(path)) File.Replace(tmp, path, null);
                    else File.Move(tmp, path);
                }
                catch
                {
                    try { File.Delete(tmp); } catch { }
                    throw;
                }
            });
        }

        /// <summary>宽容读取（对方正在写也能读，且容忍文件暂时不存在）。</summary>
        public static string Read(string path)
        {
            try
            {
                if (!File.Exists(path)) return "";
                using (var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite))
                using (var sr = new StreamReader(fs, Encoding.UTF8))
                    return sr.ReadToEnd();
            }
            catch { return ""; }
        }

        // ---------------------------------------------------------------- 输入清洗
        /// <summary>清洗会破坏 TSV / 规则文件格式的字符（服名来自 A2S，属外部输入）。</summary>
        public static string Clean(string s)
        {
            if (string.IsNullOrEmpty(s)) return "";
            return s.Replace("\t", " ").Replace("\r", " ").Replace("\n", " ").Trim();
        }

        /// <summary>去掉 BOM、U+FFFD 等不可见/损坏字符。</summary>
        public static string CleanName(string s)
        {
            s = Clean(s);
            if (s.Length > 0 && s[0] == '\uFEFF') s = s.Substring(1);
            return s.Replace("\uFFFD", "").Trim();
        }

        // ---------------------------------------------------------------- 地址校验
        /// <summary>严格 4 段点分十进制（.NET 的 IPAddress.TryParse 会接受 "103.40.13" 这种缩写，必须挡住）。</summary>
        public static bool IsStrictIPv4(string s)
        {
            if (string.IsNullOrWhiteSpace(s)) return false;
            s = s.Trim();
            if (!Regex.IsMatch(s, @"^\d{1,3}(\.\d{1,3}){3}$")) return false;
            foreach (var part in s.Split('.'))
            {
                int v;
                if (!int.TryParse(part, out v) || v < 0 || v > 255) return false;
            }
            return true;
        }
    }
}
