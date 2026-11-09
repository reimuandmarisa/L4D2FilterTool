// ============================================================================
//  TrayHost —— 常驻拦截进程的托盘图标（像 SteamServerFilter 那样在右下角）
//
//  为什么需要：`--run` 是无窗口后台进程（计划任务拉起），以前想停它只能
//  去任务管理器结束进程或敲命令；现在右键托盘图标就能看到状态、打开界面、停止退出。
//
//  实现要点：
//    · NotifyIcon 必须有自己的消息泵 —— 所以在一个独立的 STA 线程上跑
//      Application.Run(ApplicationContext)，主线程继续跑拦截循环；
//    · 菜单里的"停止拦截并退出"通过回调把主循环的停止标志置真，主循环退出后
//      正常走清理（关句柄、清心跳），进程结束；
//    · 图标优先用嵌入的 FilterTool.ico 里 16×16（托盘最清晰），退回 exe 自带图标。
// ============================================================================

using System;
using System.Drawing;
using System.Reflection;
using System.Windows.Forms;

namespace SteamServerFilterIpBlock
{
    internal static class TrayHost
    {
        private static ApplicationContext _ctx;
        private static NotifyIcon _icon;
        private static Timer _timer;
        public static string LastError = "";

        private static Icon LoadIcon()
        {
            // 1) 嵌入资源里的 16x16（托盘最清晰）
            try
            {
                var asm = Assembly.GetExecutingAssembly();
                foreach (var n in asm.GetManifestResourceNames())
                {
                    if (!n.EndsWith(".ico", StringComparison.OrdinalIgnoreCase)) continue;
                    using (var s = asm.GetManifestResourceStream(n))
                        if (s != null) return new Icon(s, new Size(16, 16));
                }
            }
            catch { }
            // 2) exe 自带的图标
            try { return Icon.ExtractAssociatedIcon(Application.ExecutablePath); } catch { }
            return SystemIcons.Shield;
        }

        private static string Clip(string s, int max)
        {
            if (string.IsNullOrEmpty(s)) return "";
            s = s.Replace("\r", " ").Replace("\n", " · ").Trim();
            return s.Length <= max ? s : s.Substring(0, max - 1) + "…";
        }

        /// <summary>在【当前线程】跑托盘消息循环，阻塞到菜单中选择退出。
        /// 请在一个 STA 后台线程上调用（常驻进程的主线程要继续跑拦截循环）。</summary>
        public static void Run(string title, Func<string> status, Action onOpenGui, Action onOpenFolder, Action onExit)
        {
            try
            {
                Application.EnableVisualStyles();
                var menu = new ContextMenuStrip();

                var miStatus = new ToolStripMenuItem("状态：…") { Enabled = false };
                menu.Items.Add(miStatus);
                // 第二行状态（例如组服列表过滤层）默认隐藏：status 回调返回多行时拆开放这里
                var miStatus2 = new ToolStripMenuItem("") { Enabled = false, Visible = false };
                menu.Items.Add(miStatus2);
                menu.Items.Add(new ToolStripSeparator());

                var miOpen = new ToolStripMenuItem("打开界面（改规则）");
                miOpen.Click += (s, e) => { try { onOpenGui(); } catch (Exception ex) { LastError = ex.Message; } };
                menu.Items.Add(miOpen);

                var miFolder = new ToolStripMenuItem("打开配置文件夹");
                miFolder.Click += (s, e) => { try { onOpenFolder(); } catch { } };
                menu.Items.Add(miFolder);

                menu.Items.Add(new ToolStripSeparator());
                var miStop = new ToolStripMenuItem("停止拦截并退出");
                miStop.Click += (s, e) =>
                {
                    try
                    {
                        if (MessageBox.Show("停止拦截并退出？\n\n" +
                                            "退出后 IP 清单与名字规则都会失效，直到下次登录（计划任务会重新拉起）\n" +
                                            "或你手动执行：schtasks /Run /TN \"SteamServerFilter IP Block\"。",
                                            "SteamServerFilter 拦截工具", MessageBoxButtons.YesNo, MessageBoxIcon.Warning)
                            != DialogResult.Yes) return;
                    }
                    catch { }
                    try { onExit(); } catch { }
                    try { if (_ctx != null) _ctx.ExitThread(); } catch { }
                };
                menu.Items.Add(miStop);

                _icon = new NotifyIcon
                {
                    Icon = LoadIcon(),
                    Text = Clip(title, 63),
                    Visible = true,
                    ContextMenuStrip = menu
                };
                _icon.DoubleClick += (s, e) => { try { onOpenGui(); } catch { } };

                _timer = new Timer { Interval = 2000 };
                _timer.Tick += (s, e) =>
                {
                    try
                    {
                        var st = status != null ? status() : "";
                        var parts = (st ?? "").Replace("\r\n", "\n").Split('\n');
                        miStatus.Text = Clip(parts.Length > 0 ? parts[0] : "", 120);
                        var second = parts.Length > 1 ? string.Join(" · ", parts, 1, parts.Length - 1) : "";
                        miStatus2.Text = Clip(second, 120);
                        miStatus2.Visible = second.Length > 0;
                        _icon.Text = Clip(title + " · " + (parts.Length > 0 ? parts[0] : ""), 63);
                    }
                    catch { }
                };
                _timer.Start();

                _ctx = new ApplicationContext();
                Application.Run(_ctx);          // 阻塞在这里直到 ExitThread
            }
            catch (Exception ex) { LastError = ex.Message; }
            finally
            {
                try { if (_timer != null) { _timer.Stop(); _timer.Dispose(); } } catch { }
                try { if (_icon != null) { _icon.Visible = false; _icon.Dispose(); } } catch { }
            }
        }

        public static bool Enabled
        {
            get
            {
                try
                {
                    var cv = Config.GetBool("tray");                 // 3.2：config.ini 优先
                    if (cv.HasValue) return cv.Value;
                    var f = System.IO.Path.Combine(IpEngine.Root, "tray.txt");
                    if (!System.IO.File.Exists(f)) return true;      // 默认开
                    return !SafeFile.Read(f).Trim().ToLowerInvariant().StartsWith("off");
                }
                catch { return true; }
            }
            set
            {
                SafeFile.Write(System.IO.Path.Combine(IpEngine.Root, "tray.txt"),
                    (value ? "on" : "off") + "\r\n# on = 常驻进程在右下角显示托盘图标（默认）；off = 不显示\r\n");
                try { Config.Set("tray", value ? "on" : "off"); } catch { }   // 3.2
            }
        }
    }
}
