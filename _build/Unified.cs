// ============================================================================
//  Unified —— SteamServerFilter 统一拦截界面（单一窗口，不分页）
//
//  核心流程：输入服务器名 → 点「添加并拦截」→
//    ① 加一条名字规则（立刻生效）
//    ② 自动解析出这台服的 IP，加进 IP 拦截清单（改名也拦得住）
//       · 解析顺序：精确 → 名字包含 → 反向包含 → 关键词（品牌）匹配
//         （浏览器显示名往往和 A2S 里的名字不同，例如 "PURE L4D2 10 #8" vs
//           "[Pure][10] L4D2"，靠共同关键词 "pure" 才能认出是同一批服）
//       · 解析不到就自动扫描已知服务器（约 20 秒）再试
//    ③ 确保 IP 拦截在跑
//
//  同一个界面里还包含：拦截总览（名字规则 + IP 地址一起显示，可删除）、
//  服务器 IP 候选（证据）、状态与开关、操作记录。
// ============================================================================

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Drawing;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading;
using System.Windows.Forms;

using Rules = SteamServerFilterRules;
using Ip = SteamServerFilterIpBlock;

namespace SteamServerFilterTool
{
    /// <summary>统一列表里的一行：要么是一条名字规则，要么是一条 IP 拦截。</summary>
    internal sealed class UniRow
    {
        public bool IsIp;
        public string Value = "";
        public string Source = "";
        public string Note = "";
        public int Hits = -1;
        public object Tag;
    }

    internal sealed class UnifiedForm : Form
    {
        // ① 输入
        private readonly Panel _viewport = new Panel { Dock = DockStyle.Fill, AutoScroll = true };
        private readonly Panel _content = new Panel();
        private readonly Panel _welcome = new Panel();
        private bool _layoutBusy;
        private readonly GroupBox _g1 = new GroupBox();
        private readonly GroupBox _g2 = new GroupBox();
        private readonly GroupBox _g3 = new GroupBox();
        private readonly GroupBox _g4 = new GroupBox();
        private readonly GroupBox _g5 = new GroupBox();
        private readonly TextBox _txtName = new TextBox();
        private readonly Button _btnPaste = new Button();
        private readonly Label _lblMatchPolicy = new Label();
        private readonly Label _welcomeState = new Label();
        private readonly Label _lblPreview = new Label();
        private readonly Label _lblLive = new Label();
        private readonly Label _lblModeHint = new Label();
        private readonly Label _welcomeTitle = new Label();
        private readonly Label _welcomeDetail = new Label();
        private readonly ToolTip _tips = new ToolTip { AutoPopDelay = 15000, InitialDelay = 400, ReshowDelay = 150 };
        private readonly Button _btnAdd = new Button();
        private readonly CheckBox _chkAutoScan = new CheckBox();
        private readonly CheckBox _chkRestart = new CheckBox();

        // ② 总览
        private readonly ListView _lvRules = new ListView();
        private readonly Button _btnDelete = new Button();
        private readonly Button _btnClearCustom = new Button();
        private readonly Button _btnStats = new Button();
        private readonly Button _btnOpen = new Button();

        // ③ 候选
        private readonly ListView _lvCand = new ListView();
        private readonly Button _btnBlockSel = new Button();
        private readonly Button _btnRefreshCand = new Button();

        // ④ 状态
        private readonly Label _lblState = new Label();
        private readonly Label _lblStateSummary = new Label();
        private readonly CheckBox _chkAutostart = new CheckBox();
        private readonly CheckBox _chkGroupDedupe = new CheckBox();
        private readonly Button _btnScanMap = new Button();
        private readonly Button _btnLocate = new Button();
        private readonly Button _btnPruneLogs = new Button();
        private readonly CheckBox _chkNameOnly = new CheckBox();
        private readonly CheckBox _chkGroupName = new CheckBox();

        // ⑤ 记录
        private readonly TextBox _txtLog = new TextBox();

        private readonly System.Windows.Forms.Timer _timer = new System.Windows.Forms.Timer();
        private List<UniRow> _rows = new List<UniRow>();
        private bool _startedLocalPolicy;
        private Dictionary<string, int> _ipEvents = new Dictionary<string, int>(StringComparer.Ordinal);

        private static Font UiFont(float size, FontStyle style)
        {
            foreach (var n in new[] { "Microsoft YaHei UI", "Microsoft YaHei", "MS Shell Dlg 2" })
            {
                try { return new Font(n, size, style); } catch { }
            }
            return new Font(SystemFonts.MessageBoxFont.FontFamily, size, style);
        }

        public UnifiedForm(bool autoStart = false)
        {
            Text = "L4D2FilterTool —— 服务器拦截工具";
            Font = UiFont(9f, FontStyle.Regular);
            // 控件位置由 LayoutSections 按当前字体重新计算，避免 WinForms 自动缩放再叠加一次。
            AutoScaleMode = AutoScaleMode.None;
            ClientSize = new Size(1120, 900);
            MinimumSize = new Size(760, 500);
            StartPosition = FormStartPosition.CenterScreen;
            FormBorderStyle = FormBorderStyle.Sizable;
            MaximizeBox = true;
            AutoScroll = false;
            Icon = Ip.AppIcon.Load(32);

            BackColor = Color.FromArgb(246, 248, 251);
            var welcome = _welcome;
            welcome.Location = new Point(12, 10); welcome.Size = new Size(1096, 58); welcome.BackColor = Color.FromArgb(229, 240, 252);
            _welcomeTitle.Text = "添加目标，减少不想看到的服务器";
            _welcomeTitle.Font = UiFont(12f, FontStyle.Bold);
            _welcomeTitle.ForeColor = Color.FromArgb(31, 72, 119);
            _welcomeDetail.Text = "粘贴名称或 IP → 添加规则 → 查看运行状态。已保存的规则可在下方删除。";
            _welcomeState.Text = "正在读取运行状态…";
            _welcomeState.Font = UiFont(9f, FontStyle.Bold);
            _welcomeState.ForeColor = Color.DimGray;
            welcome.Controls.Add(_welcomeTitle);
            welcome.Controls.Add(_welcomeDetail);
            welcome.Controls.Add(_welcomeState);
            _content.AutoScroll = false;
            _content.Location = new Point(0, 0);
            _content.Size = new Size(1120, 930);
            _viewport.Controls.Add(_content);
            Controls.Add(_viewport);
            _content.Controls.Add(welcome);

            // ---------------- ① 输入 ----------------
            var g1 = _g1;
            g1.Text = "① 添加拦截目标";
            g1.Location = new Point(12, 78); g1.Size = new Size(1096, 220);
            _content.Controls.Add(g1);
            g1.Controls.Add(new Label {
                Text = "每次输入一个服务器名、IP 或网段；指定端口可写成 203.0.113.9:27015。",
                Location = new Point(14, 22), Size = new Size(948, 20), ForeColor = Color.DimGray
            });

            _txtName.Location = new Point(14, 46); _txtName.Size = new Size(760, 28);
            _txtName.Font = UiFont(11f, FontStyle.Regular);
            _txtName.TextChanged += (s, e) => UpdatePreview();
            g1.Controls.Add(_txtName);

            _btnPaste.Text = "粘贴";
            _btnPaste.Location = new Point(782, 46); _btnPaste.Size = new Size(180, 28);
            _btnPaste.Click += (s, e) => PasteFromClipboard();
            g1.Controls.Add(_btnPaste);

            _lblMatchPolicy.Text = "名称中的数字会自动匹配同系列编号，例如 01、02。";
            _lblMatchPolicy.ForeColor = Color.DimGray;
            g1.Controls.Add(_lblMatchPolicy);

            _lblPreview.Location = new Point(14, 110); _lblPreview.Size = new Size(700, 18);
            _lblPreview.ForeColor = Color.DimGray;
            g1.Controls.Add(_lblPreview);

            _lblLive.Location = new Point(720, 110); _lblLive.Size = new Size(242, 18);
            g1.Controls.Add(_lblLive);

            _lblModeHint.Location = new Point(14, 134); _lblModeHint.Size = new Size(948, 20);
            _lblModeHint.ForeColor = Color.FromArgb(31, 72, 119);
            g1.Controls.Add(_lblModeHint);

            _btnAdd.Text = "添加并拦截";
            _btnAdd.Location = new Point(14, 160); _btnAdd.Size = new Size(420, 30);
            _btnAdd.Font = UiFont(11f, FontStyle.Bold);
            _btnAdd.Click += (s, e) => DoAddAndBlock();
            g1.Controls.Add(_btnAdd);

            _chkAutoScan.Text = "找不到 IP 时扫描（20–60 秒）";
            _chkAutoScan.Location = new Point(444, 164); _chkAutoScan.Size = new Size(290, 22);
            _chkAutoScan.Checked = true;
            g1.Controls.Add(_chkAutoScan);

            _chkRestart.Text = "添加后立即应用名字规则";
            _chkRestart.Location = new Point(740, 164); _chkRestart.Size = new Size(216, 22);
            _chkRestart.Checked = true;
            g1.Controls.Add(_chkRestart);

            // ---------------- ② 拦截总览 ----------------
            var g2 = _g2;
            g2.Text = "② 拦截清单";
            g2.Location = new Point(12, 308); g2.Size = new Size(1096, 210);
            _content.Controls.Add(g2);

            _lvRules.Location = new Point(14, 22); _lvRules.Size = new Size(948, 130);
            _lvRules.View = View.Details; _lvRules.FullRowSelect = true; _lvRules.GridLines = true;
            _lvRules.MultiSelect = true; _lvRules.HideSelection = false;
            _lvRules.Font = UiFont(9f, FontStyle.Regular);
            _lvRules.Columns.Add("类型", 64);
            _lvRules.Columns.Add("规则 / IP 地址", 292);
            _lvRules.Columns.Add("来源", 130);
            _lvRules.Columns.Add("历史命中", 86);
            _lvRules.Columns.Add("说明", 372);
            _lvRules.DoubleClick += (s, e) => CopySelected();
            _lvRules.SelectedIndexChanged += (s, e) => UpdateDeleteButton();
            g2.Controls.Add(_lvRules);

            _btnDelete.Text = "删除所选";
            _btnDelete.Location = new Point(14, 160); _btnDelete.Size = new Size(181, 30);
            _btnDelete.Click += (s, e) => DeleteSelected();
            g2.Controls.Add(_btnDelete);

            _btnClearCustom.Text = "清空全部规则…";
            _btnClearCustom.Location = new Point(205, 160); _btnClearCustom.Size = new Size(181, 30);
            _btnClearCustom.Click += (s, e) => ClearAllRules();
            g2.Controls.Add(_btnClearCustom);

            _btnStats.Text = "统计历史命中";
            _btnStats.Location = new Point(396, 160); _btnStats.Size = new Size(181, 30);
            _btnStats.Click += (s, e) => DoStats();
            g2.Controls.Add(_btnStats);

            _btnOpen.Text = "打开配置文件夹";
            _btnOpen.Location = new Point(587, 160); _btnOpen.Size = new Size(181, 30);
            _btnOpen.Click += (s, e) => { try { Process.Start(new ProcessStartInfo(Rules.Engine.Root) { UseShellExecute = true }); } catch { } };
            g2.Controls.Add(_btnOpen);

            // ---------------- ③ 候选 IP ----------------
            var g3 = _g3;
            g3.Text = "③ IP 候选（按需选择）";
            g3.Location = new Point(12, 528); g3.Size = new Size(700, 270);
            _content.Controls.Add(g3);

            _lvCand.Location = new Point(14, 22); _lvCand.Size = new Size(592, 170);
            _lvCand.View = View.Details; _lvCand.FullRowSelect = true; _lvCand.GridLines = true;
            _lvCand.MultiSelect = true; _lvCand.HideSelection = false;
            _lvCand.Font = UiFont(9f, FontStyle.Regular);
            _lvCand.Columns.Add("IP", 126);
            _lvCand.Columns.Add("命中次数", 70);
            _lvCand.Columns.Add("服务器数", 80);
            _lvCand.Columns.Add("已发现的服务器名", 314);
            g3.Controls.Add(_lvCand);

            _btnBlockSel.Text = "添加所选 IP";
            _btnBlockSel.Location = new Point(14, 200); _btnBlockSel.Size = new Size(290, 30);
            _btnBlockSel.Font = UiFont(10f, FontStyle.Bold);
            _btnBlockSel.Click += (s, e) => BlockSelectedCandidates();
            g3.Controls.Add(_btnBlockSel);

            _btnRefreshCand.Text = "刷新候选";
            _btnRefreshCand.Location = new Point(316, 200); _btnRefreshCand.Size = new Size(290, 30);
            _btnRefreshCand.Click += (s, e) => RefreshAll();
            g3.Controls.Add(_btnRefreshCand);

            // ---------------- ④ 状态 ----------------
            var g4 = _g4;
            g4.Text = "④ 运行状态与工具";
            g4.Location = new Point(724, 528); g4.Size = new Size(384, 270);
            _content.Controls.Add(g4);

            _lblStateSummary.Location = new Point(14, 22); _lblStateSummary.Size = new Size(316, 20);
            _lblStateSummary.Font = UiFont(9f, FontStyle.Bold);
            g4.Controls.Add(_lblStateSummary);
            _lblState.Location = new Point(14, 46); _lblState.Size = new Size(316, 76);
            g4.Controls.Add(_lblState);

            _chkAutostart.Text = "登录 Windows 后自动拦截";
            _chkAutostart.Location = new Point(14, 158); _chkAutostart.Size = new Size(316, 20);
            _chkAutostart.Click += (s, e) => ToggleAutostart();
            g4.Controls.Add(_chkAutostart);

            _chkGroupDedupe.Text = "组服列表去重（同名只留一条）";
            _chkGroupDedupe.Location = new Point(14, 182); _chkGroupDedupe.Size = new Size(316, 22);
            _chkGroupDedupe.Checked = Ip.GroupServerFilter.DedupeEnabled;
            _chkGroupDedupe.Click += (s, e) => ToggleGroupDedupe();
            g4.Controls.Add(_chkGroupDedupe);

            _btnScanMap.Text = "扫描已知服务器";
            _btnScanMap.Location = new Point(14, 236); _btnScanMap.Size = new Size(150, 26);
            _btnScanMap.Click += (s, e) => DoScanMap();
            g4.Controls.Add(_btnScanMap);

            _btnLocate.Text = "抓包查找 IP…";
            _btnLocate.Location = new Point(170, 236); _btnLocate.Size = new Size(160, 26);
            _btnLocate.Font = UiFont(9f, FontStyle.Bold);
            _btnLocate.Click += (s, e) => DoLocate();
            g4.Controls.Add(_btnLocate);

            _btnPruneLogs.Text = "清理过期日志…";
            _btnPruneLogs.Location = new Point(14, 266); _btnPruneLogs.Size = new Size(150, 26);
            _btnPruneLogs.Click += (s, e) => DoPruneLogs();
            g4.Controls.Add(_btnPruneLogs);

            _chkGroupName.Text = "同时从组服列表隐藏";
            _chkGroupName.Location = new Point(200, 82); _chkGroupName.Size = new Size(300, 22);
            _chkGroupName.Checked = true;
            _chkGroupName.CheckedChanged += (s, e) => UpdatePreview();
            g1.Controls.Add(_chkGroupName);

            _chkNameOnly.Text = "本次不查找 IP";
            _chkNameOnly.Location = new Point(510, 82); _chkNameOnly.Size = new Size(360, 22);
            _chkNameOnly.CheckedChanged += (s, e) => UpdatePreview();
            g1.Controls.Add(_chkNameOnly);

            // ---------------- ⑤ 记录 ----------------
            var g5 = _g5;
            g5.Text = "⑤ 操作记录";
            g5.Location = new Point(12, 808); g5.Size = new Size(1096, 108);
            _content.Controls.Add(g5);

            _txtLog.Location = new Point(14, 22); _txtLog.Size = new Size(948, 76);
            _txtLog.Multiline = true; _txtLog.ReadOnly = true; _txtLog.ScrollBars = ScrollBars.Vertical;
            _txtLog.BackColor = Color.FromArgb(250, 250, 250);
            _txtLog.Font = UiFont(9f, FontStyle.Regular);
            g5.Controls.Add(_txtLog);

            _tips.SetToolTip(_txtName, "每次添加一个服务器名、IPv4、网段或精确UDP端口。203.0.113.9:27015 仅封该UDP端口；203.0.113.9!33030 表示整IP照拦但放行 UDP 33030。仅服务器名模式下地址规则只保存。");
            _tips.SetToolTip(_lblMatchPolicy, "将名字里的数字替换为数字通配。例如“示例服务器 01”也能匹配“示例服务器 02”。其他字符按原文处理，匹配区分大小写。");
            _tips.SetToolTip(_chkGroupName, "勾选（默认）：这条名字同时写进组服列表过滤名称——名字层按 A2S 服名丢包，Steam「组战役模式服务器」列表里也会删掉这一行。取消勾选：只用于名字层丢包，组服列表保留这一行。");
            _tips.SetToolTip(_chkNameOnly, "只影响本次添加：仅写入服务器名规则，不解析 IP、不写 IP/端口清单。不会改变全局拦截模式，也不会停止已生效的 IP 拦截。直接输入 IP/端口时此选项不适用。");
            _tips.SetToolTip(_chkAutoScan, "名字找不到对应 IP 时查询已知服务器，通常约 20–60 秒。仍找不到则记入待解析名单；勾选「本次不查找 IP」时跳过这一步。");
            _tips.SetToolTip(_chkRestart, "添加新名字规则后重启当前名字过滤器，让规则及时生效。可能短暂中断名字拦截；取消后需等待常驻进程重载或手动重启过滤器。");
            _tips.SetToolTip(_btnAdd, "将输入内容加入清单。名字默认同时查找 IP；直接输入 IP 则只更新 IP 清单。处理进度和失败原因显示在 ⑤。");
            _tips.SetToolTip(_lvRules, "这里显示已配置的规则，不代表拦截进程正在运行。Ctrl / Shift 可多选，双击复制。历史命中需点击“统计历史命中”计算；名字按历史服名统计，IP 按日志事件统计。");
            _tips.SetToolTip(_btnDelete, "删除前会列出选中的规则和关联 IP 供确认。名字规则带来的 IP 会一并释放；仍被其他规则引用的 IP 保留。");
            _tips.SetToolTip(_btnClearCustom, "清除所有拦截规则：统一规则文件里的全部名字规则 + IP 清单 + 待解析队列。规则只有这一份统一文件；操作前会自动备份并要求确认。");
            _tips.SetToolTip(_btnStats, "按历史日志统计名字规则命中的服名数量和 IP 拦截事件次数。不是实时拦截状态。");
            _tips.SetToolTip(_lvCand, "根据日志和已发现的服名提供候选，不会自动把全部候选加入清单。先核对服名，再选择 IP；绿色勾号表示已在清单。");
            _tips.SetToolTip(_btnBlockSel, "把所选地址写入 IP 清单，同 IP 的其他服务器也会受影响。仅名字模式下 IP 清单不参与拦截；运行状态请查看 ④。");
            _tips.SetToolTip(_chkAutostart, "设置 Windows 计划任务，让常驻拦截在下次登录时自动运行。勾选不是当前运行状态，请查看上方状态行。");
            _tips.SetToolTip(_chkGroupDedupe, "默认开启：同一遍组服列表重建中，显示名相同的服务器只保留第一条；仅末尾 #编号 不同的名字（如 #90 / #85）也视为同一台，开头的 UTF-8 BOM 会被忽略。游戏在一次刷新里重建多遍时，每一遍会重新计数；名字为空的行不参与去重。修改后已注入的游戏会立即重读配置。");
            _tips.SetToolTip(_btnScanMap, "向日志中已知的服务器发送查询，重建服务器名与 IP 的关系，通常约 20–60 秒。");
            _tips.SetToolTip(_btnLocate, "先在 ① 输入服务器名或片段，再点击此按钮，并在 30 秒内刷新游戏的服务器浏览器。工具从应答中定位 IP 并加入清单。");
            _tips.SetToolTip(_btnPruneLogs, "删除超过保留期的旧日志，今天的日志保留。日志是候选 IP 的依据，删除后可用证据会减少。");
            _tips.SetToolTip(_lblPreview, "这是将保存的匹配规则。配置了规则后，还需要名字拦截进程运行才会生效，见 ④。");
            _tips.SetToolTip(_lblLive, "这里只检查名字是否命中已有规则，不表示过滤器正在运行；真实运行状态见 ④。");
            Disposed += (s, e) => { _timer.Dispose(); _tips.Dispose(); };
            ConfigureAppearanceAndNavigation();
            UpdatePreview();

            _timer.Interval = 1500;
            _timer.Tick += (s, e) => { RefreshState(); CheckPendingAsync(); CheckNameLayerRules(); };
            Load += (s, e) =>
            {
                if (autoStart) StartLocalPolicy();
                RefreshAll();
                if (Ip.GroupServerFilter.AutoEnabled)
                {
                    // 组服过滤是常开层：窗口启动时确保它自己的监视进程在跑（后台线程，不卡界面）
                    var residentThread = new Thread(() =>
                    {
                        string residentReport;
                        try { Ip.GroupServerFilter.EnsureResident(out residentReport); } catch { }
                    });
                    residentThread.IsBackground = true;
                    residentThread.Start();
                }
                Log("就绪：粘贴服务器名 → 点「添加并拦截」→ 到 ④ 确认拦截状态。");
                Log("名字↔IP 表里有 " + Ip.IpEngine.ReadNameMap().Count + " 条；解析不到会自动扫描。");
                if (autoStart) _timer.Start();
            };
            Resize += (s, e) => LayoutSections();
            _viewport.SizeChanged += (s, e) => LayoutSections();
            FontChanged += (s, e) => LayoutSections();
            foreach (var control in new Control[] { _lblStateSummary, _lblState, _lblModeHint, _lblLive, _welcomeState, _btnAdd })
                control.TextChanged += (s, e) => LayoutSections();
            Shown += (s, e) => FitInitialWindowToWorkArea();
            LayoutSections();
            FormClosing += (s, e) =>
            {
                if (!Ip.Blocker.IsRunning && !Ip.Blocker.IsActive && !Ip.NameLayer.IsRunning && !_startedLocalPolicy) return;
                var r = MessageBox.Show(this,
                    "当前是本窗口正在执行拦截，关闭界面会停止本窗口的名字和 IP 拦截。\n\n" +
                    "常驻进程不受影响；如果希望下次登录自动拦截，请勾选「登录 Windows 后自动拦截」。\n\n" +
                    "是 = 停止本窗口拦截并退出\n否 = 取消",
                    "本窗口正在拦截", MessageBoxButtons.YesNo, MessageBoxIcon.Warning);
                if (r != DialogResult.Yes) { e.Cancel = true; return; }
                Ip.Blocker.Stop();
                Ip.NameLayer.Stop();
                _startedLocalPolicy = false;
                if (Ip.IpEngine.ResidentPid() == Process.GetCurrentProcess().Id)
                    Ip.IpEngine.ClearHeartbeat();
            };
        }

        private void ConfigureAppearanceAndNavigation()
        {
            var groups = new[] { _g1, _g2, _g3, _g4, _g5 };
            for (int i = 0; i < groups.Length; i++)
            {
                groups[i].BackColor = Color.White;
                groups[i].TabIndex = i + 1;
                groups[i].Padding = new Padding(14);
            }
            foreach (var button in new[] { _btnPaste, _btnAdd, _btnDelete, _btnClearCustom, _btnStats,
                _btnOpen, _btnBlockSel, _btnRefreshCand, _btnScanMap, _btnLocate, _btnPruneLogs })
            {
                button.FlatStyle = FlatStyle.Flat;
                button.FlatAppearance.BorderColor = Color.FromArgb(205, 214, 224);
                button.BackColor = Color.FromArgb(247, 249, 252);
                button.ForeColor = Color.FromArgb(35, 52, 72);
                button.Cursor = Cursors.Hand;
            }
            _btnAdd.BackColor = Color.FromArgb(35, 94, 166);
            _btnAdd.ForeColor = Color.White;
            _btnAdd.FlatAppearance.BorderColor = _btnAdd.BackColor;
            _btnAdd.FlatAppearance.MouseOverBackColor = Color.FromArgb(28, 78, 142);
            _btnAdd.FlatAppearance.MouseDownBackColor = Color.FromArgb(24, 65, 120);
            _btnClearCustom.ForeColor = Color.FromArgb(165, 49, 49);
            _txtLog.BorderStyle = BorderStyle.FixedSingle;
            _lvRules.BorderStyle = _lvCand.BorderStyle = BorderStyle.FixedSingle;
            _lvRules.ShowItemToolTips = _lvCand.ShowItemToolTips = true;
            _txtName.AccessibleName = "服务器名、IP 或网段";
            _btnAdd.AccessibleName = "添加当前拦截目标";
            _lvRules.AccessibleName = "已保存的拦截规则";
            _lvCand.AccessibleName = "服务器 IP 候选";
            _txtLog.AccessibleName = "操作记录";
            _txtLog.TabStop = false;
            _welcome.TabStop = false;
            var inputOrder = new Control[] { _txtName, _btnPaste, _chkGroupName, _chkNameOnly,
                _chkAutoScan, _chkRestart, _btnAdd };
            for (int i = 0; i < inputOrder.Length; i++) inputOrder[i].TabIndex = i;
            _lvRules.TabIndex = _lvCand.TabIndex = 0;
            var rulesOrder = new Control[] { _btnDelete, _btnClearCustom, _btnStats, _btnOpen };
            for (int i = 0; i < rulesOrder.Length; i++) rulesOrder[i].TabIndex = i + 1;
            _btnBlockSel.TabIndex = 1;
            _btnRefreshCand.TabIndex = 2;
            _chkAutostart.TabIndex = 0;
            _btnScanMap.TabIndex = 1;
            _btnLocate.TabIndex = 2;
            _btnPruneLogs.TabIndex = 3;
            AcceptButton = _btnAdd;
        }

        private void FitInitialWindowToWorkArea()
        {
            if (WindowState != FormWindowState.Normal) return;
            var area = Screen.FromControl(this).WorkingArea;
            int w = Math.Min(Width, Math.Max(MinimumSize.Width, area.Width - 40));
            int h = Math.Min(Height, Math.Max(MinimumSize.Height, area.Height - 40));
            Size = new Size(w, h);
            CenterToScreen();
            LayoutSections();
        }

        private int UiPx(int value)
        {
            return (int)Math.Ceiling(value * Math.Max(1.0, Font.Height / 17.0));
        }

        private int LabelHeight(Label label, int width)
        {
            return TextRenderer.MeasureText(label.Text.Length == 0 ? "示例" : label.Text, label.Font,
                new Size(Math.Max(1, width), int.MaxValue), TextFormatFlags.WordBreak | TextFormatFlags.NoPrefix).Height + UiPx(4);
        }

        private int PlaceRow(Control parent, Control[] controls, int top, int width)
        {
            int gap = UiPx(8), left = UiPx(14), rowHeight = 0, x = left;
            foreach (var c in controls)
            {
                int padding = UiPx(c is Button ? 30 : 28);
                int desired = Math.Min(width, TextRenderer.MeasureText(c.Text, c.Font).Width + padding);
                int height = Math.Max(UiPx(30), TextRenderer.MeasureText(c.Text, c.Font,
                    new Size(Math.Max(1, desired - padding), int.MaxValue),
                    TextFormatFlags.WordBreak | TextFormatFlags.NoPrefix).Height + UiPx(10));
                if (x > left && x + desired > left + width) { x = left; top += rowHeight + gap; rowHeight = 0; }
                c.SetBounds(x, top, desired, height);
                rowHeight = Math.Max(rowHeight, height);
                x += desired + gap;
            }
            return top + rowHeight;
        }

        private void LayoutSections()
        {
            if (_layoutBusy || _g5.Parent == null) return;
            _layoutBusy = true;
            int scrollY = Math.Max(0, -_viewport.AutoScrollPosition.Y);
            _viewport.SuspendLayout();
            _content.SuspendLayout();
            try
            {
                int margin = UiPx(12), inset = UiPx(14), gap = UiPx(10);
                int contentWidth = Math.Max(1, _viewport.Width - SystemInformation.VerticalScrollBarWidth - 2);
                int width = Math.Max(UiPx(300), contentWidth - margin * 2);
                int inner = Math.Max(UiPx(240), width - inset * 2);
                int y = gap;

                bool wideBanner = width >= UiPx(900);
                int badgeWidth = wideBanner ? Math.Min(UiPx(320), inner / 3) : inner;
                int titleWidth = wideBanner ? inner - badgeWidth - gap : inner;
                _welcomeTitle.SetBounds(inset, UiPx(12), titleWidth, LabelHeight(_welcomeTitle, titleWidth));
                _welcomeState.SetBounds(wideBanner ? inset + titleWidth + gap : inset,
                    wideBanner ? UiPx(12) : _welcomeTitle.Bottom + UiPx(4), badgeWidth, LabelHeight(_welcomeState, badgeWidth));
                int bannerBottom = Math.Max(_welcomeTitle.Bottom, _welcomeState.Bottom);
                _welcomeDetail.SetBounds(inset, bannerBottom + UiPx(4), inner, LabelHeight(_welcomeDetail, inner));
                _welcome.SetBounds(margin, y, width, _welcomeDetail.Bottom + UiPx(12));
                y = _welcome.Bottom + gap;

                var inputHint = _g1.Controls.OfType<Label>().First(c => c != _lblPreview && c != _lblLive && c != _lblModeHint && c != _lblMatchPolicy);
                int top = UiPx(24);
                inputHint.SetBounds(inset, top, inner, LabelHeight(inputHint, inner));
                top = inputHint.Bottom + UiPx(5);
                int pasteWidth = Math.Min(UiPx(100), Math.Max(UiPx(76), inner / 4));
                int inputWidth = Math.Max(UiPx(120), inner - pasteWidth - gap);
                int inputHeight = Math.Max(_txtName.PreferredHeight, UiPx(30));
                _txtName.SetBounds(inset, top, inputWidth, inputHeight);
                _btnPaste.SetBounds(inset + inputWidth + gap, top, pasteWidth, inputHeight);
                top += inputHeight + UiPx(6);
                _lblMatchPolicy.SetBounds(inset, top, inner, LabelHeight(_lblMatchPolicy, inner));
                top = _lblMatchPolicy.Bottom + UiPx(2);
                top = PlaceRow(_g1, new Control[] { _chkGroupName, _chkNameOnly }, top, inner) + UiPx(6);
                bool stackPreview = inner < UiPx(800);
                int liveWidth = stackPreview ? inner : Math.Min(UiPx(230), inner / 3);
                int previewWidth = stackPreview ? inner : inner - liveWidth - gap;
                int previewHeight = stackPreview ? UiPx(26) : Math.Max(UiPx(26), LabelHeight(_lblLive, liveWidth));
                _lblPreview.SetBounds(inset, top, previewWidth, previewHeight);
                _lblLive.SetBounds(stackPreview ? inset : inset + previewWidth + gap,
                    stackPreview ? _lblPreview.Bottom + UiPx(2) : top, liveWidth, LabelHeight(_lblLive, liveWidth));
                top = Math.Max(_lblPreview.Bottom, _lblLive.Bottom) + UiPx(4);
                _lblModeHint.SetBounds(inset, top, inner, LabelHeight(_lblModeHint, inner));
                top = _lblModeHint.Bottom + UiPx(5);
                top = PlaceRow(_g1, new Control[] { _btnAdd, _chkAutoScan, _chkRestart }, top, inner);
                _g1.SetBounds(margin, y, width, top + inset);
                y = _g1.Bottom + gap;

                int rulesTableHeight = UiPx(156);
                int ruleButtonsTop = UiPx(24) + rulesTableHeight + UiPx(8);
                int ruleButtonsBottom = PlaceRow(_g2, new Control[] { _btnDelete, _btnClearCustom, _btnStats, _btnOpen }, ruleButtonsTop, inner);
                int rulesHeight = ruleButtonsBottom + inset;
                _g2.SetBounds(margin, y, width, rulesHeight);
                _lvRules.SetBounds(inset, UiPx(24), inner, rulesTableHeight);
                int ruleColumns = Math.Max(1, _lvRules.ClientSize.Width - SystemInformation.VerticalScrollBarWidth);
                _lvRules.Columns[0].Width = UiPx(64);
                _lvRules.Columns[2].Width = UiPx(125);
                _lvRules.Columns[3].Width = UiPx(86);
                int rest = ruleColumns - UiPx(64 + 125 + 86);
                _lvRules.Columns[1].Width = Math.Max(UiPx(125), rest / 2);
                _lvRules.Columns[4].Width = Math.Max(UiPx(125), rest - _lvRules.Columns[1].Width);
                y = _g2.Bottom + gap;

                bool stacked = width < UiPx(930);
                int stateWidth = stacked ? width : Math.Max(UiPx(365), (int)(width * 0.36));
                int candWidth = stacked ? width : Math.Max(UiPx(260), width - stateWidth - gap);
                int stateInner = Math.Max(UiPx(220), stateWidth - inset * 2);

                top = UiPx(24);
                _lblStateSummary.SetBounds(inset, top, stateInner, LabelHeight(_lblStateSummary, stateInner));
                top = _lblStateSummary.Bottom + UiPx(4);
                _lblState.SetBounds(inset, top, stateInner, Math.Max(UiPx(84), LabelHeight(_lblState, stateInner)));
                top = _lblState.Bottom + UiPx(8);
                int autostartHeight = Math.Max(UiPx(30), TextRenderer.MeasureText(_chkAutostart.Text, _chkAutostart.Font,
                    new Size(Math.Max(1, stateInner - UiPx(28)), int.MaxValue), TextFormatFlags.WordBreak).Height + UiPx(10));
                _chkAutostart.SetBounds(inset, top, stateInner, autostartHeight);
                top = _chkAutostart.Bottom + UiPx(5);
                top = PlaceRow(_g4, new Control[] { _chkGroupDedupe }, top, stateInner) + UiPx(5);
                int stateButtonsBottom = PlaceRow(_g4, new Control[] { _btnScanMap, _btnLocate, _btnPruneLogs }, top, stateInner);
                int stateHeight = Math.Max(UiPx(230), stateButtonsBottom + inset);

                int candInner = Math.Max(UiPx(220), candWidth - inset * 2);
                int candButtonsTop = UiPx(24) + UiPx(150) + UiPx(8);
                int candButtonsBottom = PlaceRow(_g3, new Control[] { _btnBlockSel, _btnRefreshCand }, candButtonsTop, candInner);
                int candHeight = Math.Max(UiPx(270), candButtonsBottom + inset);
                int bottomHeight = Math.Max(candHeight, stateHeight);
                _g3.SetBounds(margin, y, candWidth, bottomHeight);
                _g4.SetBounds(stacked ? margin : margin + candWidth + gap, stacked ? y + bottomHeight + gap : y, stateWidth, stacked ? stateHeight : bottomHeight);
                _lvCand.SetBounds(inset, UiPx(24), candInner, UiPx(150));
                _lvCand.Columns[0].Width = Math.Min(UiPx(135), Math.Max(UiPx(90), candInner / 4));
                _lvCand.Columns[1].Width = Math.Min(UiPx(78), Math.Max(UiPx(58), candInner / 7));
                _lvCand.Columns[2].Width = Math.Min(UiPx(80), Math.Max(UiPx(58), candInner / 7));
                _lvCand.Columns[3].Width = Math.Max(UiPx(100), candInner - _lvCand.Columns[0].Width - _lvCand.Columns[1].Width - _lvCand.Columns[2].Width - SystemInformation.VerticalScrollBarWidth);
                y = stacked ? _g4.Bottom + gap : _g3.Bottom + gap;

                int logHeight = UiPx(110);
                int available = _viewport.Height - y - logHeight - gap;
                if (available > 0)
                {
                    int rulesExtra = available / 3;
                    int candExtra = available / 3;
                    logHeight += available - rulesExtra - candExtra;
                    _g2.Height += rulesExtra;
                    _lvRules.Height += rulesExtra;
                    foreach (var b in new[] { _btnDelete, _btnClearCustom, _btnStats, _btnOpen }) b.Top += rulesExtra;
                    _g3.Top += rulesExtra;
                    _g3.Height += candExtra;
                    _lvCand.Height += candExtra;
                    _btnBlockSel.Top += candExtra;
                    _btnRefreshCand.Top += candExtra;
                    _g4.Top = stacked ? _g3.Bottom + gap : _g3.Top;
                    if (!stacked) _g4.Height = _g3.Height;
                    y = stacked ? _g4.Bottom + gap : _g3.Bottom + gap;
                }
                _g5.SetBounds(margin, y, width, logHeight);
                _txtLog.SetBounds(inset, UiPx(24), inner, Math.Max(UiPx(60), logHeight - UiPx(24) - inset));
                _content.Size = new Size(contentWidth, _g5.Bottom + gap);
                _viewport.AutoScrollMinSize = new Size(0, _content.Height);
                _viewport.HorizontalScroll.Enabled = false;
                _viewport.VerticalScroll.Enabled = true;
                _viewport.PerformLayout();
                _viewport.AutoScrollPosition = new Point(0, scrollY);
            }
            finally
            {
                _content.ResumeLayout(false);
                _viewport.ResumeLayout(true);
                _viewport.AutoScrollPosition = new Point(0, scrollY);
                _layoutBusy = false;
            }
        }

        internal int CheckResponsiveLayout(Action<string> report)
        {
            LayoutSections();
            int issues = 0;
            if (_content.Width > _viewport.ClientSize.Width + 1 || _viewport.HorizontalScroll.Visible)
            {
                report("  内容未适配视口：内容=" + _content.Bounds + " 视口=" + _viewport.ClientSize + " 滚动=" + _viewport.AutoScrollPosition + " 横向=" + _viewport.HorizontalScroll.Visible);
                issues++;
            }
            bool stacked = _g2.Width < UiPx(930);
            if (stacked && (_g4.Top < _g3.Bottom || _g4.Left != _g3.Left || _g3.Width != _g2.Width))
            {
                report("  窄窗口没有切换到上下排列");
                issues++;
            }
            foreach (var label in new[] { _welcomeTitle, _welcomeDetail, _welcomeState, _lblMatchPolicy, _lblLive, _lblModeHint, _lblStateSummary, _lblState })
                if (LabelHeight(label, label.Width) > label.Height)
                {
                    report("  文字高度不足：" + label.Text);
                    issues++;
                }
            report("  内容宽度=" + _content.Width + " 视口=" + _viewport.ClientSize + " 排列=" + (stacked ? "单列" : "双列"));
            return issues;
        }

        private void Log(string m)
        {
            _txtLog.AppendText("[" + DateTime.Now.ToString("HH:mm:ss") + "] " + m + "\r\n");
        }

        // V-29: 本窗口自己跑着名字层时，block_rules.txt 一变必须重载 ——
        // 否则界面显示"名字层运行中"，实际还在按旧规则匹配（常驻路径有监控，GUI 路径原来没有）。
        private DateTime _nameRuleStamp = DateTime.MinValue;
        private DateTime _localConfigStamp = DateTime.MinValue;
        private DateTime _lastLocalRecovery = DateTime.MinValue;
        private DateTime _lastLocalBeat = DateTime.MinValue;

        private void CheckNameLayerRules()
        {
            if (!_startedLocalPolicy && !Ip.NameLayer.IsRunning && !Ip.Blocker.IsRunning) return;
            try
            {
                var f = Path.Combine(Rules.Engine.Root, "block_rules.txt");
                var st = File.Exists(f) ? File.GetLastWriteTime(f) : DateTime.MinValue;
                var configStamp = Ip.Config.ConfigStamp();
                bool changed = st != _nameRuleStamp || configStamp != _localConfigStamp;
                bool wantName = Ip.NameLayer.Enabled || Ip.NameLayer.NameOnlyMode;
                bool recover = wantName && !Ip.NameLayer.IsRunning;
                if (changed || (recover && (DateTime.Now - _lastLocalRecovery).TotalSeconds >= 5))
                {
                    _nameRuleStamp = st;
                    _localConfigStamp = configStamp;
                    _lastLocalRecovery = DateTime.Now;
                    ReloadNameFilter();
                }
                if ((DateTime.Now - _lastLocalBeat).TotalSeconds >= 3)
                {
                    _lastLocalBeat = DateTime.Now;
                    Ip.IpEngine.WriteHeartbeat(Ip.Blocker.IsActive,
                        recover ? "名字层未运行：" + Ip.NameLayer.LastError : Ip.Blocker.LastError);
                }
            }
            catch (Exception ex) { Log("× 重载名字层规则失败：" + ex.Message); }
        }

        // 后台把"待解析"的服名补成 IP 拦截（每 60 秒最多一次；扫描在后台线程跑，不卡界面）
        private DateTime _lastPendingCheck = DateTime.MinValue;
        private volatile bool _pendingBusy;

        private void CheckPendingAsync()
        {
            if (_pendingBusy) return;
            if (Ip.IpEngine.ReadPending().Count == 0) return;
            if ((DateTime.Now - _lastPendingCheck).TotalSeconds < 60) return;
            _lastPendingCheck = DateTime.Now;
            _pendingBusy = true;
            var t = new Thread(() =>
            {
                int added = 0;
                try
                {
                    added = Ip.IpEngine.ResolvePending(true, 5, m =>
                    {
                        try { BeginInvoke(new Action(() => Log(m))); } catch { }
                    });
                }
                catch { }
                finally { _pendingBusy = false; }
                if (added > 0)
                {
                    try
                    {
                        BeginInvoke(new Action(() =>
                        {
                            if (Ip.Blocker.IsActive) { Ip.Blocker.Stop(); Ip.Blocker.Start(Ip.IpEngine.ReadEntries(), Ip.IpEngine.ExcludeUdpForNameLayer()); }
                            RefreshAll();
                        }));
                    }
                    catch { }
                }
            });
            t.IsBackground = true;
            t.Start();
        }

        // ---------------------------------------------------------- 输入区
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

        /// <summary>组服列表过滤是独立层：这次「添加规则」已经把名字写进它的规则文件，
        /// 若这一层开着但监视进程不在，后台拉起（不卡界面；新规则会被自动热加载）。</summary>
        private void EnsureGroupFilterResident()
        {
            try
            {
                if (!Ip.GroupServerFilter.AutoEnabled) return;
                if (Ip.GroupServerFilter.ResidentRunning()) return;
                var th = new Thread(() =>
                {
                    try { string report; Ip.GroupServerFilter.EnsureResident(out report); } catch { }
                });
                th.IsBackground = true;
                th.Start();
                Log("· 组服列表过滤这一层开着：已在后台启动监视进程（新规则会自动热加载）。");
            }
            catch { }
        }

        private string CurrentRule(out string error)
        {
            error = null;
            var name = _txtName.Text.Trim();
            if (name.Length == 0) { error = "请先输入服务器名。"; return null; }
            return Rules.Engine.NewRuleFromName(name, true);
        }

        private void UpdatePreview()
        {
            var name = _txtName.Text.Trim();
            bool nameOnly = Ip.NameLayer.NameOnlyMode;
            bool addNameOnly = _chkNameOnly.Checked;
            bool alsoGroup = _chkGroupName.Checked;
            string scopeText = alsoGroup
                ? "按名称过滤，并从组服列表隐藏匹配项"
                : "按名称过滤，保留组服列表中的显示";
            bool isIp = Ip.IpEngine.IsValidAddress(name);
            string endpointIp; int endpointPort;
            bool isEndpoint = Ip.IpEngine.TryParseEndpoint(name, out endpointIp, out endpointPort);
            _chkGroupName.Enabled = !isIp;
            _chkNameOnly.Enabled = !isIp;
            _chkAutoScan.Enabled = !isIp && !addNameOnly && !nameOnly;
            _chkRestart.Enabled = !isIp;
            _lblMatchPolicy.Text = isIp ? "直接添加地址：不会生成服务器名规则。"
                : "名称中的数字会自动匹配同系列编号，例如 01、02；其他文字区分大小写。";
            _lblModeHint.Text = name.Length == 0 ? "默认按名称过滤并查找关联 IP；可按需调整本次选项。"
                : isIp ? "本次保存地址规则。整 IP / 网段可能影响同一地址上的其他服务器。"
                : scopeText + (addNameOnly || nameOnly ? "；本次不查找 IP。" : "；同时查找关联 IP。");
            if (nameOnly) _lblModeHint.Text += " 当前为仅名称模式，IP 清单暂不参与拦截。";
            _lblModeHint.ForeColor = nameOnly ? Color.DarkGoldenrod : Color.FromArgb(31, 72, 119);
            _btnAdd.Text = isEndpoint ? "添加 UDP 端口规则"
                : isIp ? "添加 IP 规则"
                : addNameOnly || nameOnly ? "添加名称规则" : "添加并拦截";
            if (!_adding) _btnAdd.Enabled = name.Length > 0;
            _lblPreview.AutoEllipsis = true;
            if (name.Length == 0)
            {
                _lblPreview.Text = "规则预览：输入后显示";
                _lblPreview.ForeColor = Color.DimGray;
                _lblLive.Text = "";
                return;
            }
            if (isIp)
            {
                _lblPreview.Text = isEndpoint
                    ? "精确 UDP 规则：只拦 " + endpointIp + " 的 UDP " + endpointPort + " 端口，其他端口不受这条规则影响。"
                    : "识别为 IP / 网段：仅更新 IP 清单，不生成名字规则。";
                _lblPreview.ForeColor = Color.DimGray;
                _lblLive.Text = nameOnly ? "当前策略不使用 IP 清单" : "运行状态请查看 ④";
                _lblLive.ForeColor = nameOnly ? Color.DarkGoldenrod : Color.DimGray;
                return;
            }
            string err;
            var rule = CurrentRule(out err);
            _lblPreview.Text = rule == null ? err : "规则预览：" + rule;
            _tips.SetToolTip(_lblPreview, _lblPreview.Text + "\n规则已保存不代表正在拦截，请查看运行状态。");
            _lblPreview.ForeColor = rule == null ? Color.Firebrick : Color.DimGray;
            if (rule == null)
            {
                _lblLive.Text = "请修正输入后再添加";
                _lblLive.ForeColor = Color.Firebrick;
                return;
            }
            var hit = Rules.Engine.MatchedRule(name);
            _lblLive.Text = hit != null ? "已有规则匹配此名称" : "尚未添加此名称";
            _lblLive.ForeColor = hit != null ? Color.SeaGreen : Color.DarkGoldenrod;
        }

        // ------------------------------------------------- 核心：添加并拦截
        private bool _adding;

        private void DoAddAndBlock()
        {
            // V-23: 解析失败时会扫描 20-60 秒（进度回调里 DoEvents 分发消息），
            //       没有栅栏的话手快连点会重入：并发追加规则 + 两轮 64 线程扫描 + 交错写文件。
            if (_adding) { Log("· 上一次「添加并拦截」还在处理中，请稍候。"); return; }
            _adding = true;
            _btnAdd.Enabled = false;
            try { DoAddAndBlockCore(); }
            finally { _adding = false; UpdatePreview(); }
        }

        private void DoAddAndBlockCore()
        {
            var name = _txtName.Text.Trim();
            if (name.Length == 0) { Log("· 请先输入服务器名（或直接粘贴它的 IP）。"); return; }

            // 输入框同时支持 IP / 网段：有些新服在映射表里查不到名字，直接从
            // 服务器浏览器里复制它的 IP 粘进来即可。
            if (Ip.IpEngine.IsValidAddress(name))
            {
                // V-08: 超大网段（/0~/8）按 IP 拦截是双向丢包 = 本机这些地址流量全断，必须显式确认
                int bpf; long bhosts;
                if (Ip.IpEngine.IsBroadRange(name, out bpf, out bhosts))
                {
                    if (MessageBox.Show(this,
                            name + " 是超大网段（/" + bpf + "，约 " + bhosts + " 个地址）。\n\n" +
                            "IP 拦截是双向丢包 —— 加进去会让本机与这些地址之间的流量全部中断。\n\n确认要加吗？",
                            "超大网段确认", MessageBoxButtons.YesNo, MessageBoxIcon.Warning) != DialogResult.Yes)
                    {
                        Log("· 已取消：超大网段未加入。");
                        return;
                    }
                }
                try
                {
                    var list0 = Ip.IpEngine.ReadEntries();
                    var act0 = Ip.IpEngine.UpsertEntry(list0, name, "手动添加");
                    Ip.IpEngine.WriteEntries(list0);
                    string base0; List<int> ex0;
                    Ip.IpEngine.SplitExempt(name, out base0, out ex0);
                    Log("· " + (act0 == "added" ? "已直接把 IP 加入拦截清单：" : "已更新清单里的这个地址：") + name +
                        (ex0.Count > 0 ? ("（放行端口 " + string.Join(",", ex0.Select(p => p.ToString()).ToArray()) + "，其它端口照拦）") : "") +
                        "，IP 清单共 " + list0.Count + " 条");
                    if (Ip.NameLayer.NameOnlyMode)
                    {
                        Log("· 当前全局模式不使用 IP 清单：这条地址/UDP端口规则已保存，但暂不参与当前拦截；本次添加选项不改变全局模式。");
                        _txtName.Clear();
                        RefreshAll();
                        return;
                    }
                    if (Ip.Blocker.IsActive) { Ip.Blocker.Stop(); Ip.Blocker.Start(Ip.IpEngine.ReadEntries(), Ip.IpEngine.ExcludeUdpForNameLayer()); }
                    else
                    {
                        bool fr;
                        Ip.IpEngine.ReadHeartbeat(out fr);
                        if (!fr)
                        {
                            Ip.Blocker.Start(Ip.IpEngine.ReadEntries(), Ip.IpEngine.ExcludeUdpForNameLayer());
                            if (Ip.Blocker.IsActive) Log("· 已启动 IP 拦截。");
                            else Log("· IP 拦截启动失败：" + Ip.Blocker.LastError);
                        }
                    }
                    _txtName.Clear();
                    RefreshAll();
                }
                catch (Exception ex) { Log("× 失败：" + ex.Message); }
                return;
            }

            string err;
            var rule = CurrentRule(out err);
            if (rule == null)
            {
                Log("× " + err);
                MessageBox.Show(this, err, "无法添加", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                return;
            }

            try
            {
                // ---- 第 1 步：名字层 ----
                var already = Rules.Engine.MatchedRule(name);
                if (already != null)
                {
                    Log("· 名字层已有规则覆盖（命中 " + already + "），跳过加规则。");
                }
                else
                {
                    var added = Rules.Engine.AppendCustom(name, rule, _chkGroupName.Checked);
                    Log(added ? ("· 名字规则已加入 custom.txt：" + rule) : "· custom.txt 里已有这条规则。");
                    if (!string.IsNullOrEmpty(Rules.Engine.LastGroupFilterNote))
                        Log("· " + Rules.Engine.LastGroupFilterNote);
                    var active = Rules.Engine.GetActiveProfile();
                    if (!Rules.Engine.ActiveComponents().Contains("custom")) active = active + "+custom";
                    var cnt = Rules.Engine.ApplyCombo(active);
                    Log("· 已重新生成 block_rules.txt：" + cnt + " 条生效规则（规则文件 " + active + "）");
                    if (_chkRestart.Checked)
                    {
                        Log("· 刷新名字拦截规则 ...");
                        ReloadNameFilter();
                    }
                    else Log("· 未立即刷新名字拦截规则（常驻进程会自动重载；也可用 --name-layer on 启用内置名字层）。");
                }

                // 组服列表过滤层：这次添加已同步写入它的规则文件；这一层开着就确保监视进程在跑
                EnsureGroupFilterResident();

                // ---- 第 2 步：解析 IP ----
                // 复选框只影响这次添加；全局 mode 由 ④/CLI 管理，不在这里改变。
                if (_chkNameOnly.Checked)
                {
                    Log("· 本次不查找 IP：已跳过 IP 解析（未修改 IP 清单）。");
                    _txtName.Clear();
                    RefreshAll();
                    return;
                }
                string how;
                List<string> matchedNames;
                var ips = Rules.IpBridge.PreviewIps(name, out how, out matchedNames);

                if (ips.Count == 0 && _chkAutoScan.Checked)
                {
                    Log("· 未找到关联 IP，正在扫描已知服务器（通常 20–60 秒）…");
                    Application.DoEvents();
                    var res = Ip.IpEngine.SweepNames(64, 1200,
                        (d, t) => { if (d % 500 == 0) { Log("   进度 " + d + "/" + t); Application.DoEvents(); } });
                    Log("· 扫描完成：查了 " + res.Scanned + " 个 endpoint，拿到名字 " + res.Found +
                        " 个，映射表新增 " + res.Added + " 条。");
                    ips = Rules.IpBridge.PreviewIps(name, out how, out matchedNames);
                }

                if (ips.Count == 0)
                {
                    var queued = Ip.IpEngine.AddPending(name, already ?? rule);
                    Log("· 暂时解析不出它的 IP —— 已记入「待解析」名单（" + Ip.IpEngine.PendingFile + "）。");
                    Log("  现在：名字规则已经生效，过滤器会先把它拦下来。");
                    Log("  之后：过滤器拦下它时日志会记录它的 IP:端口，本工具会自动扫描并把它补进 IP 拦截名单");
                    Log("        （本窗口每 60 秒查一次；常驻进程也在查，所以关掉窗口也会自动补）。");
                    if (queued) Log("  待解析服名：" + string.Join(" | ", Ip.IpEngine.ReadPending().Select(k => k.Name).Take(8).ToArray()));
                    RefreshAll();
                    return;
                }

                Log("· 名字→IP 解析：" + how + "；匹配到 " + matchedNames.Count + " 个服名，得到 " +
                    ips.Count + " 个 IP。");
                foreach (var n2 in matchedNames.Take(6)) Log("    服名: " + n2);
                if (matchedNames.Count > 6) Log("    ...（其余 " + (matchedNames.Count - 6) + " 个省略）");

                if (ips.Count > 1)
                {
                    var q = "解析到 " + ips.Count + " 个 IP：\n\n" + string.Join("\n", ips.Take(12).ToArray()) +
                            (ips.Count > 12 ? "\n..." : "") +
                            "\n\n匹配到 " + matchedNames.Count + " 个服名（依据：" + how + "）。\n\n全部加入 IP 拦截清单？";
                    if (MessageBox.Show(this, q, "确认按 IP 拦", MessageBoxButtons.YesNo, MessageBoxIcon.Question) != DialogResult.Yes)
                    {
                        Log("· 已取消按 IP 拦（名字规则已加）。");
                        RefreshAll();
                        return;
                    }
                }

                List<string> addedIps;
                Ip.IpEngine.AddNameToBlockList(name, out addedIps, already ?? rule);
                if (addedIps.Count == 0) Log("· 这些地址已经在拦截清单里了（已记录关联，删这条名字规则时会一并释放）。");
                else
                {
                    Log("· 已加入拦截清单：" + string.Join(", ", addedIps.ToArray()));
                    if (Ip.Blocker.IsActive) { Ip.Blocker.Stop(); Ip.Blocker.Start(Ip.IpEngine.ReadEntries(), Ip.IpEngine.ExcludeUdpForNameLayer()); }
                }
                if (!string.IsNullOrEmpty(Ip.IpEngine.LastAddNote)) Log("· " + Ip.IpEngine.LastAddNote);

                // ---- 第 3 步：确保 IP 拦截在跑 ----
                bool fresh;
                Ip.IpEngine.ReadHeartbeat(out fresh);
                if (!Ip.Blocker.IsActive && !fresh)
                {
                    Ip.Blocker.Start(Ip.IpEngine.ReadEntries(), Ip.IpEngine.ExcludeUdpForNameLayer());
                    if (Ip.Blocker.IsActive) Log("· 已启动 IP 拦截（本窗口）。想常驻请勾选「开机自动启动 IP 拦截」。");
                    else Log("· IP 拦截启动失败：" + Ip.Blocker.LastError);
                }

                _txtName.Clear();
                RefreshAll();
            }
            catch (Exception ex)
            {
                Log("× 失败：" + ex.Message);
                MessageBox.Show(this, ex.Message, "失败", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }

        // ------------------------------------------------------- 总览与删除
        private void RefreshRows(bool withStats = false)
        {
            _rows = new List<UniRow>();
            try
            {
                foreach (var r in Rules.Engine.ReadActiveRulesDetailed())
                    _rows.Add(new UniRow { IsIp = false, Value = r.Rule, Source = r.Source, Note = r.Note, Tag = r });
            }
            catch (Exception ex) { Log("× 读取名字规则失败：" + ex.Message); }

            foreach (var e in Ip.IpEngine.ReadEntries())
                _rows.Add(new UniRow { IsIp = true, Value = e.Address, Source = "ip_block.txt", Note = e.Note, Tag = e });

            if (withStats)
            {
                try
                {
                    var corpus = Rules.Engine.LoadCorpus();
                    foreach (var row in _rows.Where(x => !x.IsIp))
                        row.Hits = Rules.Engine.CountHits(row.Value, corpus);
                }
                catch { }
                _ipEvents = new Dictionary<string, int>(StringComparer.Ordinal);
                try
                {
                    foreach (var c in Ip.IpEngine.MineCandidates()) _ipEvents[c.Ip] = c.Events;
                }
                catch { }
                foreach (var row in _rows.Where(x => x.IsIp))
                {
                    int ev;
                    string statsIp; int statsPort;
                    bool endpointStats = Ip.IpEngine.TryParseEndpoint(row.Value, out statsIp, out statsPort);
                    if (!endpointStats) { List<int> exempt; Ip.IpEngine.SplitExempt(row.Value, out statsIp, out exempt); }
                    row.Hits = _ipEvents.TryGetValue(statsIp, out ev) ? ev : 0;
                    if (endpointStats) row.Note += "（次数为整 IP 历史统计，非此端口命中）";
                }
            }

            _lvRules.BeginUpdate();
            _lvRules.Items.Clear();
            foreach (var row in _rows)
            {
                var it = new ListViewItem(row.IsIp ? "IP" : "名字");
                it.SubItems.Add(row.Value);
                it.SubItems.Add(row.Source);
                it.SubItems.Add(row.Hits < 0 ? "-" : row.Hits.ToString());
                it.SubItems.Add(row.Note);
                it.Tag = row;
                if (row.IsIp) it.ForeColor = Color.FromArgb(0, 100, 160);
                _lvRules.Items.Add(it);
            }
            _lvRules.EndUpdate();
            UpdateDeleteButton();
        }

        private void UpdateDeleteButton()
        {
            _btnDelete.Text = _lvRules.SelectedItems.Count > 1
                ? ("删除选中 " + _lvRules.SelectedItems.Count + " 条")
                : "删除选中";
        }

        private void CopySelected()
        {
            if (_lvRules.SelectedItems.Count == 0) return;
            var txt = string.Join("\r\n", _lvRules.SelectedItems.Cast<ListViewItem>().Select(i => i.Text + "  " + i.SubItems[1].Text).ToArray());
            try { Clipboard.SetText(txt); Log("· 已复制：" + txt.Replace("\r\n", " | ")); }
            catch (Exception ex) { Log("× 复制失败：" + ex.Message); }
        }

        private void DeleteSelected()
        {
            if (_lvRules.SelectedItems.Count == 0) { Log("· 请先在 ② 里选中要删除的条目。"); return; }
            var rows = _lvRules.SelectedItems.Cast<ListViewItem>().Select(i => (UniRow)i.Tag).ToList();
            var sb = new StringBuilder();
            sb.AppendLine("确定删除下面 " + rows.Count + " 条吗？");
            sb.AppendLine();
            foreach (var r in rows) sb.AppendLine("  [" + (r.IsIp ? "IP" : "名字") + "] " + r.Value + "     ← " + r.Source);

            // 预告：删这条名字规则会顺带释放哪些 IP
            var previewIps = new List<string>();
            foreach (var rule in rows.Where(r => !r.IsIp).Select(r => r.Value))
            {
                foreach (var l in Ip.IpEngine.ReadLinks())
                    if (string.Equals(l.Rule, rule, StringComparison.Ordinal) && !previewIps.Contains(l.Ip))
                        previewIps.Add(l.Ip);
            }
            sb.AppendLine();
            sb.AppendLine("名字规则会从所属规则档里移除（先备份到 rules-profiles\\.backup\\）；");
            if (previewIps.Count > 0)
            {
                sb.AppendLine("并【一并释放】这些由它带来的 IP（会从 ip_block.txt 删掉）：");
                foreach (var ip in previewIps) sb.AppendLine("    " + ip);
                sb.AppendLine("（如果这些 IP 还被别的名字规则引用，则保留。）");
            }
            else sb.AppendLine("（这些名字规则没有关联的 IP，IP 清单不受影响。）");
            sb.AppendLine("单独选中的 IP 条目直接移除。");
            if (MessageBox.Show(this, sb.ToString(), "删除", MessageBoxButtons.YesNo, MessageBoxIcon.Warning) != DialogResult.Yes) return;

            try
            {
                var ipRows = rows.Where(r => r.IsIp).Select(r => r.Value).ToList();
                var nameRows = rows.Where(r => !r.IsIp).Select(r => r.Value).ToList();

                foreach (var rule in nameRows)
                {
                    var changed = Rules.Engine.DeleteRule(rule);
                    Log(changed.Count > 0 ? ("· 已从 " + string.Join(", ", changed.ToArray()) + " 删除规则：" + rule)
                                          : ("· 没找到这条规则：" + rule));
                }
                if (nameRows.Count > 0)
                {
                    var cnt = Rules.Engine.ApplyCombo(Rules.Engine.GetActiveProfile());
                    Log("· 已重新生成 block_rules.txt：" + cnt + " 条生效规则。");
                }

                // ---- 一并释放这些名字规则带来的 IP ----
                if (nameRows.Count > 0)
                {
                    var released = new List<string>();
                    var kept = new List<string>();
                    var pendNames = new List<string>();
                    foreach (var rule in nameRows)
                    {
                        // 删除不受添加模式影响：一律连带释放（否则会留下孤儿 IP）
                        List<string> k, p;
                        released.AddRange(Ip.IpEngine.ReleaseIpsForRule(rule, out k, out p));
                        kept.AddRange(k);
                        pendNames.AddRange(p);
                    }
                    released = released.Distinct(StringComparer.Ordinal).ToList();
                    kept = kept.Distinct(StringComparer.Ordinal).ToList();
                    if (released.Count > 0)
                        Log("· 已一并释放 " + released.Count + " 个 IP：" + string.Join(", ", released.ToArray()));
                    if (kept.Count > 0)
                        Log("· 这些 IP 保留（还有别的名字规则在用）：" + string.Join(", ", kept.ToArray()));
                    if (released.Count == 0 && kept.Count == 0)
                        Log("· 这些名字规则没有关联的 IP，IP 清单未变动。");

                    // 待解析名单里属于这些名字的条目也一起清掉（不再想拦它了）
                    var links = Ip.IpEngine.ReadLinks();
                    foreach (var pn in pendNames.Distinct(StringComparer.Ordinal))
                    {
                        if (links.Any(l => string.Equals(l.Name, pn, StringComparison.Ordinal))) continue;
                        Ip.IpEngine.RemovePending(pn);
                        Log("· 已从待解析名单移除：" + pn);
                    }
                }

                if (ipRows.Count > 0)
                {
                    var entries = Ip.IpEngine.ReadEntries().Where(e => !ipRows.Contains(e.Address)).ToList();
                    Ip.IpEngine.WriteEntries(entries);
                    foreach (var ip in ipRows)
                    {
                        string endpointIp; int endpointPort;
                        if (!Ip.IpEngine.TryParseEndpoint(ip, out endpointIp, out endpointPort))
                        {
                            string baseIp; List<int> exempt;
                            Ip.IpEngine.SplitExempt(ip, out baseIp, out exempt);
                            Ip.IpEngine.RemoveLinksForIp(baseIp);
                        }
                    }
                    Log("· 已从 IP 清单移除 " + ipRows.Count + " 条（精确 UDP 端口规则只移除自身），剩余 " + entries.Count + " 条。");
                }

                if (ipRows.Count > 0 || nameRows.Count > 0)
                {
                    var entries = Ip.IpEngine.ReadEntries();
                    if (Ip.Blocker.IsActive) { Ip.Blocker.Stop(); Ip.Blocker.Start(entries, Ip.IpEngine.ExcludeUdpForNameLayer()); }
                }

                // V-06: 引擎只在启动时读规则 —— 删了规则不重启过滤器，被删的服会继续被拦，
                // 而界面/清单三个信号都显示"删好了"，用户会被误导。这里必须重启。
                if (nameRows.Count > 0)
                {
                    Log("· 正在重启名字过滤器让删除生效 ...");
                    try
                    {
                        ReloadNameFilter();
                    }
                    catch (Exception ex2)
                    {
                        Log("★ 重启失败：" + ex2.Message);
                        Log("★ 注意：名字过滤器内存里仍有被删的规则，它还会继续拦截这些服务器。");
                        Log("   请等待常驻进程自动重载，或执行 FilterTool.exe --name-layer on 后重试。");
                    }
                }
                RefreshAll();
            }
            catch (Exception ex) { Log("× 删除失败：" + ex.Message); }
        }

        /// <summary>清除所有拦截规则：统一规则文件里的全部名字规则 + IP 清单 + 待解析队列。
        /// 规则只有这一份统一文件（名字层丢包与组服列表删行共用），所以不再区分「自定义/默认」。</summary>
        private void ClearAllRules()
        {
            if (MessageBox.Show(this, "清除所有拦截规则？\n\n" +
                    "会清空：\n" +
                    "· 统一规则文件里的全部名字规则（rules-profiles\\custom.txt）\n" +
                    "· IP 清单 ip_block.txt（含精确 UDP 端口规则）\n" +
                    "· 待解析队列 pending_resolve.tsv\n\n" +
                    "操作前会自动备份；之后可从 rules-profiles\\.backup\\ 恢复。", "清除所有拦截规则",
                    MessageBoxButtons.YesNo, MessageBoxIcon.Warning) != DialogResult.Yes) return;
            try
            {
                Rules.Engine.EnsureUnifiedRules();
                Rules.Engine.BackupProfileFile(Rules.Engine.CustomFile);
                try { if (File.Exists(Ip.IpEngine.IpFile)) Rules.Engine.BackupProfileFile(Ip.IpEngine.IpFile); }
                catch (Exception exBak) { Log("× 备份 IP 清单失败：" + exBak.Message); }

                int ruleCount = 0;
                try
                {
                    var rules = Rules.Engine.ReadProfileRules("custom");
                    ruleCount = rules.Count;
                    // 与「删除选中」一致：先释放每条名字规则带来的 IP，再整体清空清单
                    foreach (var r in rules)
                    {
                        List<string> kept, pend;
                        Ip.IpEngine.ReleaseIpsForRule(r, out kept, out pend);
                        foreach (var pn in pend) Ip.IpEngine.RemovePending(pn);
                    }
                }
                catch (Exception exRel) { Log("× 清理关联 IP 失败：" + exRel.Message); }

                foreach (var kv in Ip.IpEngine.ReadPending()) Ip.IpEngine.RemovePending(kv.Name);

                var ipCount = Ip.IpEngine.ReadEntries().Count;
                Ip.IpEngine.WriteEntries(new List<Ip.IpEntry>());
                Ip.IpEngine.WriteLinks(new List<Ip.IpEngine.IpLink>());

                Rules.Engine.ResetCustomFile();
                var cnt = Rules.Engine.ApplyCombo("custom");
                Log("· 已清除所有拦截规则：名字规则 " + ruleCount + " 条、IP 规则 " + ipCount + " 条；现在 " + cnt + " 条生效规则。");

                if (Ip.Blocker.IsActive) { Ip.Blocker.Stop(); Ip.Blocker.Start(Ip.IpEngine.ReadEntries(), Ip.IpEngine.ExcludeUdpForNameLayer()); }
                try { ReloadNameFilter(); } catch { }
                RefreshAll();
            }
            catch (Exception ex) { Log("× 失败：" + ex.Message); }
        }

        private void DoStats()
        {
            Cursor = Cursors.WaitCursor;
            Log("· 正在统计（名字规则扫 Logs 语料，IP 条目扫拉黑次数）...");
            Application.DoEvents();
            try { RefreshRows(true); Log("· 统计完成。"); }
            catch (Exception ex) { Log("× 统计失败：" + ex.Message); }
            finally { Cursor = Cursors.Default; }
        }

        // ------------------------------------------------------- 候选与开关
        private void BlockSelectedCandidates()
        {
            if (_lvCand.SelectedItems.Count == 0) { Log("· 请先在 ③ 里选中要拦的 IP。"); return; }
            var entries = Ip.IpEngine.ReadEntries();
            int added = 0;
            foreach (ListViewItem it in _lvCand.SelectedItems)
            {
                var c = (Ip.Candidate)it.Tag;
                var note = c.Names.Count > 0
                    ? (c.Sample.Length > 40 ? c.Sample.Substring(0, 40) + "…" : c.Sample)
                    : ("日志拉黑 " + c.Events + " 次");
                var act = Ip.IpEngine.UpsertEntry(entries, c.Ip, note);   // V-02: 按基础地址判重/更新
                if (act == "added") added++;
            }
            Ip.IpEngine.WriteEntries(entries);
            Log("· 已加入 " + added + " 个 IP（IP 清单共 " + entries.Count + " 条）。");
            if (Ip.Blocker.IsActive) { Ip.Blocker.Stop(); Ip.Blocker.Start(entries, Ip.IpEngine.ExcludeUdpForNameLayer()); }
            RefreshAll();
        }

        private void ReloadNameFilter()
        {
            using (var resident = Ip.IpEngine.ResidentInstance())
            {
                if (resident != null)
                {
                    Log("· 常驻进程会自动重载内置名字规则。");
                    return;
                }
            }
            Ip.Blocker.Stop();
            Ip.NameLayer.Stop();
            StartLocalPolicy();
        }

        private void StartLocalPolicy()
        {
            using (var resident = Ip.IpEngine.ResidentInstance())
            {
                if (resident != null)
                {
                    Log("· 已检测到常驻拦截进程，界面只读取状态，不重复启动。");
                    return;
                }
            }
            bool nameOnly = Ip.NameLayer.NameOnlyMode;
            if ((Ip.NameLayer.Enabled || nameOnly) && !Ip.NameLayer.IsRunning)
            {
                var result = Ip.NameLayer.Start();
                Log(result == "OK" ? "· 已启动内置名字拦截。" : "× 内置名字拦截启动失败：" + result);
                _startedLocalPolicy |= Ip.NameLayer.IsRunning;
            }
            // 旧版本按名字解析可能留下"共享 IP 的裸 IP 封锁"（黑喵等服被同一 IP 连坐）。
            // 启动拦截前先修复；幂等，失败不阻塞主流程。
            try { Ip.IpEngine.RepairSharedNameBlocks(Log); } catch (Exception ex) { Log("× 共享 IP 修复失败：" + ex.Message); }
            var entries = Ip.IpEngine.ReadEntries();
            if (entries.Count == 0 && !nameOnly)
            {
                Ip.Blocker.Stop();
                Log("· IP 清单为空，不启动 IP 句柄；名字拦截状态见 ④。");
                return;
            }
            var res = Ip.Blocker.Start(entries, Ip.IpEngine.ExcludeUdpForNameLayer());
            _startedLocalPolicy |= Ip.Blocker.IsActive;
            Log(res == "OK" ? "· 当前策略拦截已启动。" : "× IP/委托拦截启动失败：" + res);
        }

        private void ToggleAutostart()
        {
            try
            {
                Log(_chkAutostart.Checked ? ("· 安装开机自启：" + Ip.IpEngine.InstallAutostart())
                                          : ("· 移除开机自启：" + Ip.IpEngine.RemoveAutostart()));
                _chkAutostart.Checked = Ip.IpEngine.AutostartInstalled();
            }
            catch (Exception ex) { Log("× 失败：" + ex.Message); }
        }

        private void ToggleGroupDedupe()
        {
            try
            {
                string report;
                if (!Ip.GroupServerFilter.SetDedupe(_chkGroupDedupe.Checked, out report))
                {
                    _chkGroupDedupe.Checked = !_chkGroupDedupe.Checked;
                    Log("× " + report);
                    return;
                }
                Log("· " + report);
                _chkGroupDedupe.Checked = Ip.GroupServerFilter.DedupeEnabled;
            }
            catch (Exception ex)
            {
                _chkGroupDedupe.Checked = !_chkGroupDedupe.Checked;
                Log("× 切换组服列表去重失败：" + ex.Message);
            }
        }

        private void DoScanMap()
        {
            if (MessageBox.Show(this,
                    "扫描服务器 IP 来重建『服务器名↔IP』关系？\n\n对日志里出现过的全部 endpoint 各发一次 A2S 查询，约 20-60 秒。", 
                    "扫描", MessageBoxButtons.YesNo, MessageBoxIcon.Question) != DialogResult.Yes) return;
            Cursor = Cursors.WaitCursor;
            _btnScanMap.Enabled = false;
            Log("· 开始扫描服务器 IP ...");
            Application.DoEvents();
            try
            {
                var res = Ip.IpEngine.SweepNames(64, 1200,
                    (d, t) => { if (d % 500 == 0) { Log("   进度 " + d + "/" + t); Application.DoEvents(); } });
                Log("· 扫描完成：endpoint " + res.Scanned + " 个，拿到名字 " + res.Found +
                    " 个，映射表新增 " + res.Added + " 条；表内共 " + Ip.IpEngine.ReadNameMap().Count + " 条。");
            }
            catch (Exception ex) { Log("× 扫描失败：" + ex.Message); }
            finally { Cursor = Cursors.Default; _btnScanMap.Enabled = true; }
        }



        /// <summary>清理超过保留期的日志（与计划任务同一套逻辑）。</summary>
        private void DoPruneLogs()
        {
            var days = Ip.IpEngine.LogRetentionDays;
            if (MessageBox.Show(this,
                    "删除 " + days + " 天以前的日志？\n\n目录：" + Ip.IpEngine.LogDir +
                    "\n保留：" + days + " 天（可用 --logs-keep 改）\n今天的日志永不删除。\n\n" +
                    "提示：日志是「IP 候选」的证据来源，保留期太短会让候选列表变空。",
                    "清理旧日志", MessageBoxButtons.YesNo, MessageBoxIcon.Question) != DialogResult.Yes) return;
            Cursor = Cursors.WaitCursor;
            _btnPruneLogs.Enabled = false;
            try
            {
                Ip.IpEngine.PruneLogs(days, Log);
                RefreshState();
            }
            catch (Exception ex) { Log("× 清理失败：" + ex.Message); }
            finally { Cursor = Cursors.Default; _btnPruneLogs.Enabled = true; }
        }

        /// <summary>抓包定位：抓 30 秒 A2S 报文，把匹配到的服的真实 IP 加进拦截清单。</summary>
        private void DoLocate()
        {
            var s = _txtName.Text.Trim();
            if (s.Length == 0) { Log("· 请先在 ① 里输入服务器名（或名字片段），再点「抓包定位 IP」。"); return; }
            if (MessageBox.Show(this,
                    "抓包定位「" + s + "」？\n\n点「是」之后请立刻去 L4D2 里刷新一次服务器浏览器（让它出现在列表里），\n" +
                    "工具会抓 30 秒 A2S 报文，然后自动读出它的 IP 并加入拦截清单。\n\n" +
                    "（pktmon 只读抓包，不影响游戏流量；抓完自动删除原始文件）",
                    "抓包定位", MessageBoxButtons.YesNo, MessageBoxIcon.Question) != DialogResult.Yes) return;

            _btnLocate.Enabled = false;
            var t = new Thread(() =>
            {
                try
                {
                    var hits = Ip.CapLocate.Capture(30, m => { try { BeginInvoke(new Action(() => Log(m))); } catch { } });
                    var matched = Ip.CapLocate.Match(hits, s);
                    BeginInvoke(new Action(() =>
                    {
                        if (matched.Count == 0)
                        {
                            Log("× 抓到的 " + hits.Count + " 个应答里没有匹配「" + s + "」的服。");
                            Log("  请确认刷新时它真的出现在服务器列表里（列表里能看到它再等几秒），然后重试。");
                            return;
                        }
                        Log("· 抓包匹配到 " + matched.Count + " 个：");
                        foreach (var h in matched.Take(10)) Log("    " + h.Ip + ":" + h.Port + "   " + h.Name);

                        // V-28: 关键词兜底可能一次命中一大批服；多 IP 时必须让用户确认，
                        //        与「添加并拦截」的多 IP 确认保持一致。
                        var ipSet = matched.Select(h => h.Ip).Distinct(StringComparer.Ordinal).ToList();
                        if (ipSet.Count > 1)
                        {
                            var q = "抓包匹配到 " + matched.Count + " 个服、共 " + ipSet.Count + " 个不同 IP：\n\n" +
                                    string.Join("\n", ipSet.Take(12).ToArray()) +
                                    (ipSet.Count > 12 ? "\n..." : "") +
                                    "\n\n全部加入 IP 拦截清单？";
                            if (MessageBox.Show(this, q, "确认按 IP 拦", MessageBoxButtons.YesNo, MessageBoxIcon.Question) != DialogResult.Yes)
                            {
                                Log("· 已取消（未改动 IP 清单）。");
                                return;
                            }
                        }

                        var entries = Ip.IpEngine.ReadEntries();
                        int added = 0;
                        foreach (var h in matched)
                        {
                            var linkRule = Rules.Engine.MatchedRule(h.Name) ?? s;
                            var act = Ip.IpEngine.UpsertEntry(entries, h.Ip, h.Name + "（抓包定位）");
                            if (act == "added")
                            {
                                Ip.IpEngine.AddLink(linkRule, h.Ip, h.Name, true, "capture");
                                added++;
                            }
                            else Ip.IpEngine.AddLink(linkRule, h.Ip, h.Name, false, "capture");
                        }
                        if (added > 0)
                        {
                            Ip.IpEngine.WriteEntries(entries);
                            Log("· 已加入 IP 拦截清单 " + added + " 个：" +
                                string.Join(", ", matched.Select(h => h.Ip).Distinct().ToArray()));
                            Ip.IpEngine.RemovePending(s);
                            if (Ip.Blocker.IsActive) { Ip.Blocker.Stop(); Ip.Blocker.Start(Ip.IpEngine.ReadEntries(), Ip.IpEngine.ExcludeUdpForNameLayer()); }
                        }
                        else Log("· 这些 IP 都已在拦截清单里（关联已记录）。");
                        RefreshAll();
                    }));
                }
                catch (Exception ex) { try { BeginInvoke(new Action(() => Log("× 抓包定位失败：" + ex.Message))); } catch { } }
                finally { try { BeginInvoke(new Action(() => { _btnLocate.Enabled = true; })); } catch { } }
            });
            t.IsBackground = true;
            t.Start();
        }
        // ----------------------------------------------------------- 刷新
        // V-13: schtasks 查询要起子进程，1.5 秒一次太重；缓存 30 秒。
        private bool _autostartCached;
        private DateTime _autostartAt = DateTime.MinValue;
        private bool _warnedFilterDead;
        private bool _warnedBothLayers;
        private bool _logTaskCached;
        private DateTime _logTaskAt = DateTime.MinValue;
        private bool LogTaskCached()
        {
            if ((DateTime.Now - _logTaskAt).TotalSeconds > 30)
            {
                try { _logTaskCached = Ip.IpEngine.LogTaskInstalled(); } catch { }
                _logTaskAt = DateTime.Now;
            }
            return _logTaskCached;
        }

        private bool AutostartCached()
        {
            if ((DateTime.Now - _autostartAt).TotalSeconds > 30)
            {
                try { _autostartCached = Ip.IpEngine.AutostartInstalled(); } catch { }
                _autostartAt = DateTime.Now;
            }
            return _autostartCached;
        }

        private void RefreshState()
        {
            try
            {
                var rules = Rules.Engine.ReadEngineRules();
                var mangled = rules.Count(Rules.Engine.RuleIsMangled);
                var inSync = Rules.Engine.IsRulesFileInSync();
                var entries = Ip.IpEngine.ReadEntries();
                bool fresh; string hbState;
                // V-13: 心跳里带了 blocking 标记，直接用它判断"是否真在丢包"；
                //       V-03: 重载失败时 blocking=no，这里就不会再误报"拦截中"。
                var hbBlocking = Ip.IpEngine.HeartbeatBlocking(out fresh, out hbState);
                bool running = Ip.Blocker.IsActive || (fresh && hbBlocking);
                var autostart = AutostartCached();

                bool nf; string ns;
                Ip.IpEngine.HeartbeatBlocking(out nf, out ns);
                bool nameRunning = Ip.NameLayer.IsRunning || (nf && Ip.IpEngine.HeartbeatField("namelayer") == "yes");
                // 旧版引擎（SteamServerFilter.exe）是否在跑；本工具常驻进程不算“旧版”。
                bool filterDead = Ip.Lifecycle.LegacyProcesses().Length == 0;

                bool noNameLayer = filterDead && !nameRunning;
                bool nameOnly = Ip.NameLayer.NameOnlyMode;
                bool validEncoding = Rules.Engine.RulesFileIsValidUtf8();
                bool ruleProblem = mangled > 0 || !inSync || !validEncoding;
                _lblStateSummary.Text = ruleProblem ? "规则需要检查"
                    : noNameLayer ? "名称拦截未运行"
                    : (!nameOnly && !running) ? "名称拦截运行中 · IP 未运行"
                    : "当前拦截策略已运行";
                _lblStateSummary.ForeColor = ruleProblem || noNameLayer ? Color.Firebrick
                    : (!nameOnly && !running) ? Color.DarkGoldenrod : Color.SeaGreen;

                _welcomeState.Text = _lblStateSummary.Text;
                _welcomeState.ForeColor = _lblStateSummary.ForeColor;
                _tips.SetToolTip(_welcomeState, "此处显示名称与 IP 的运行状态；组服列表过滤由独立进程执行。详细信息见 ④。");

                string nameOwner = Ip.NameLayer.IsRunning ? "本窗口（内置）"
                    : nameRunning ? "常驻进程（内置）" : filterDead ? "未运行" : "旧版过滤器";
                if (nameRunning && !filterDead) nameOwner += " + 旧版";
                string ipState = nameOnly ? "当前策略不使用 IP 清单"
                    : Ip.Blocker.IsActive ? "本窗口运行中"
                    : fresh ? (hbBlocking ? "常驻进程运行中" : "常驻进程未执行 IP 拦截") : "未启动";
                var sb = new StringBuilder();
                sb.AppendLine("名字拦截：" + nameOwner + " · " + rules.Count + " 条规则");
                sb.AppendLine("IP 拦截：" + ipState + " · " + entries.Count + " 条地址");
                sb.AppendLine("策略：" + (nameOnly ? "仅服务器名" : "服务器名 + IP") + " · 自启" + (autostart ? "已开启" : "未开启"));
                sb.AppendLine("名字/IP 记录 " + Ip.IpEngine.ReadNameMap().Count + " 条 · 待解析 " + Ip.IpEngine.ReadPending().Count + " 个");
                _lblState.Text = sb.ToString().TrimEnd();
                _lblState.ForeColor = Color.Black;
                _tips.SetToolTip(_lblState, "规则同步：" + (inSync ? "正常" : "需重新生成") +
                    "；编码：" + (validEncoding ? "UTF-8 正常" : "异常") + "；无效规则：" + mangled +
                    "\n今日日志拦截事件：" + Rules.Engine.TodayBlockCount() + "；本窗口 IP 丢包：" + Interlocked.Read(ref Ip.Blocker.Dropped) +
                    "\n日志保留 " + Ip.IpEngine.LogRetentionDays + " 天；自动清理任务：" + (LogTaskCached() ? "已安装" : "未安装") +
                    "\n常驻心跳：" + (fresh ? hbState : "未检测到") + "；内置名字层已封端点：" + Ip.IpEngine.HeartbeatFieldOr("nameblocked"));
                if (!filterDead && nameRunning && !_warnedBothLayers)
                {
                    _warnedBothLayers = true;
                    Log("★ 两个名字层同时在跑（SteamServerFilter + 自建）—— 建议只留一个，它们各开一个 WinDivert 句柄。");
                }
                else if (filterDead || !nameRunning) _warnedBothLayers = false;
                if (noNameLayer && !_warnedFilterDead)
                {
                    _warnedFilterDead = true;
                    Log("★ 没有任何名字层在运行（SteamServerFilter 没跑，内置名字层也关着）——规则目前不生效。");
                    Log("  可在命令行执行 FilterTool.exe --name-layer on 启用内置名字层。");
                }
                else if (!noNameLayer) _warnedFilterDead = false;
                _chkAutostart.Checked = autostart;
                _chkGroupDedupe.Checked = Ip.GroupServerFilter.DedupeEnabled;
                // 添加选项保留用户选择，状态刷新只读取全局拦截模式。
            }
            catch (Exception ex) { Log("× 刷新状态失败：" + ex.Message); }
        }

        private void RefreshAll()
        {
            Cursor = Cursors.WaitCursor;
            try
            {
                Rules.Engine.EnsureCustomFile();
                RefreshRows(false);
                RefreshState();

                var cands = Ip.IpEngine.MineCandidates();
                _lvCand.BeginUpdate();
                _lvCand.Items.Clear();
                foreach (var c in cands)
                {
                    var it = new ListViewItem(c.IsBlocked ? ("✔ " + c.Ip) : c.Ip);
                    it.SubItems.Add(c.Events.ToString());
                    it.SubItems.Add(c.Names.Count.ToString());
                    it.SubItems.Add(c.Sample);
                    it.Tag = c;
                    if (c.IsBlocked) it.ForeColor = Color.SeaGreen;
                    _lvCand.Items.Add(it);
                }
                _lvCand.EndUpdate();
                UpdatePreview();
            }
            catch (Exception ex) { Log("× 刷新失败：" + ex.Message); }
            finally { Cursor = Cursors.Default; }
        }
    }
}
