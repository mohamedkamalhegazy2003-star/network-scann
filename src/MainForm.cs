using System.Text;

namespace NetworkScan;

public class MainForm : Form
{
    // ---- controls ----
    Button btnScan, btnLang, btnSave;
    ComboBox cmb;
    Label lblAdapter, lblStatus;
    ProgressBar bar;
    TabControl tabs;
    TabPage tOv, tDev, tDiag, tSec, tSol;
    FlowLayoutPanel cards, fixPanel;
    RichTextBox rtbSummary, rtbSol;
    DataGridView gDev, gDiag, gSec;

    readonly Dictionary<string, Label> cardTitle = new();
    readonly Dictionary<string, Label> cardValue = new();
    readonly List<(Button b, string ar, string en, string key)> fixBtns = new();

    Report rep;
    bool scanning;

    static readonly (string key, string ar, string en)[] CardDefs =
    {
        ("type", "نوع الاتصال", "Connection"),
        ("adapter", "كرت الشبكة", "Adapter"),
        ("ip", "IP / الراوتر", "IP / Gateway"),
        ("link", "الوصلة / الإشارة", "Link / Signal"),
        ("down", "سرعة التحميل", "Download"),
        ("up", "سرعة الرفع", "Upload"),
        ("ping", "Ping / Jitter", "Ping / Jitter"),
        ("loss", "فقد الحزم", "Packet loss"),
        ("dns", "سرعة DNS", "DNS time"),
        ("devices", "عدد الأجهزة", "Devices"),
        ("perf", "تقييم الأداء", "Performance"),
        ("sec", "تقييم الأمان", "Security"),
    };

    public MainForm()
    {
        Text = "Network Scan";
        Width = 1100;
        Height = 740;
        MinimumSize = new Size(900, 600);
        StartPosition = FormStartPosition.CenterScreen;
        Font = new Font("Segoe UI", 10f);
        try { Icon = Icon.ExtractAssociatedIcon(Application.ExecutablePath); } catch { }

        BuildUi();
        LoadAdapters();
        ApplyLang();
    }

    // =================================================================== UI
    void BuildUi()
    {
        var top = new Panel { Dock = DockStyle.Top, Height = 92, Padding = new Padding(10) };
        btnScan = new Button { Width = 170, Height = 40, Left = 10, Top = 8, BackColor = Color.FromArgb(0, 120, 215), ForeColor = Color.White, FlatStyle = FlatStyle.Flat, Font = new Font("Segoe UI", 11f, FontStyle.Bold) };
        btnScan.FlatAppearance.BorderSize = 0;
        btnScan.Click += async (s, e) => await RunScan();

        lblAdapter = new Label { Left = 195, Top = 16, AutoSize = true };
        cmb = new ComboBox { Left = 300, Top = 12, Width = 380, DropDownStyle = ComboBoxStyle.DropDownList };

        btnSave = new Button { Left = 700, Top = 10, Width = 130, Height = 32 };
        btnSave.Click += (s, e) => SaveReport();
        btnLang = new Button { Left = 840, Top = 10, Width = 110, Height = 32 };
        btnLang.Click += (s, e) => { L.Ar = !L.Ar; ApplyLang(); };

        bar = new ProgressBar { Left = 10, Top = 56, Width = 1040, Height = 8, Style = ProgressBarStyle.Marquee, Visible = false, Anchor = AnchorStyles.Top | AnchorStyles.Left | AnchorStyles.Right };
        lblStatus = new Label { Left = 10, Top = 66, AutoSize = true, ForeColor = Color.DimGray };

        top.Controls.AddRange(new Control[] { btnScan, lblAdapter, cmb, btnSave, btnLang, bar, lblStatus });

        tabs = new TabControl { Dock = DockStyle.Fill };
        tOv = new TabPage(); tDev = new TabPage(); tDiag = new TabPage(); tSec = new TabPage(); tSol = new TabPage();
        tabs.TabPages.AddRange(new[] { tOv, tDev, tDiag, tSec, tSol });

        // Overview
        cards = new FlowLayoutPanel { Dock = DockStyle.Top, AutoSize = true, AutoSizeMode = AutoSizeMode.GrowAndShrink, Padding = new Padding(6), WrapContents = true };
        foreach (var c in CardDefs)
        {
            var p = new Panel { Width = 255, Height = 74, BorderStyle = BorderStyle.FixedSingle, Margin = new Padding(6), BackColor = Color.White };
            var t = new Label { Dock = DockStyle.Top, Height = 24, ForeColor = Color.Gray, Padding = new Padding(6, 4, 6, 0) };
            var v = new Label { Dock = DockStyle.Fill, Font = new Font("Segoe UI", 12f, FontStyle.Bold), Padding = new Padding(6, 2, 6, 0), Text = "—" };
            p.Controls.Add(v); p.Controls.Add(t);
            cards.Controls.Add(p);
            cardTitle[c.key] = t; cardValue[c.key] = v;
        }
        rtbSummary = new RichTextBox { Dock = DockStyle.Fill, ReadOnly = true, BorderStyle = BorderStyle.None, Font = new Font("Segoe UI", 11f), BackColor = Color.White };
        tOv.Controls.Add(rtbSummary);
        tOv.Controls.Add(cards);

        // Devices
        gDev = MakeGrid();
        foreach (var n in new[] { "ip", "name", "mac", "type", "vendor", "ping", "ports", "notes" }) gDev.Columns.Add(n, n);
        tDev.Controls.Add(gDev);

        // Diagnosis & Security
        gDiag = MakeGrid();
        gSec = MakeGrid();
        foreach (var g in new[] { gDiag, gSec })
        {
            foreach (var n in new[] { "sev", "title", "detail", "fix" }) g.Columns.Add(n, n);
            g.Columns["sev"].FillWeight = 9;
            g.Columns["title"].FillWeight = 22;
            g.Columns["detail"].FillWeight = 33;
            g.Columns["fix"].FillWeight = 36;
        }
        tDiag.Controls.Add(gDiag);
        tSec.Controls.Add(gSec);

        // Solutions
        fixPanel = new FlowLayoutPanel { Dock = DockStyle.Top, AutoSize = true, AutoSizeMode = AutoSizeMode.GrowAndShrink, Padding = new Padding(6) };
        AddFix("flush", "مسح كاش DNS", "Flush DNS cache");
        AddFix("cf", "DNS: Cloudflare 1.1.1.1", "DNS: Cloudflare 1.1.1.1");
        AddFix("google", "DNS: Google 8.8.8.8", "DNS: Google 8.8.8.8");
        AddFix("dnsauto", "DNS تلقائي", "DNS automatic");
        AddFix("renew", "تجديد IP", "Renew IP");
        AddFix("perf", "وضع الأداء العالي", "High-performance power plan");
        AddFix("reset", "إصلاح الشبكة (Winsock/IP)", "Repair network (Winsock/IP)");
        rtbSol = new RichTextBox { Dock = DockStyle.Fill, ReadOnly = true, BorderStyle = BorderStyle.None, Font = new Font("Segoe UI", 11f), BackColor = Color.White };
        tSol.Controls.Add(rtbSol);
        tSol.Controls.Add(fixPanel);

        Controls.Add(tabs);
        Controls.Add(top);
    }

    DataGridView MakeGrid()
    {
        var g = new DataGridView
        {
            Dock = DockStyle.Fill,
            ReadOnly = true,
            AllowUserToAddRows = false,
            AllowUserToDeleteRows = false,
            RowHeadersVisible = false,
            BackgroundColor = Color.White,
            BorderStyle = BorderStyle.None,
            AutoSizeColumnsMode = DataGridViewAutoSizeColumnsMode.Fill,
            AutoSizeRowsMode = DataGridViewAutoSizeRowsMode.AllCells,
            SelectionMode = DataGridViewSelectionMode.FullRowSelect,
            EnableHeadersVisualStyles = true
        };
        g.DefaultCellStyle.WrapMode = DataGridViewTriState.True;
        g.DefaultCellStyle.Padding = new Padding(2, 4, 2, 4);
        return g;
    }

    void AddFix(string key, string ar, string en)
    {
        var b = new Button { AutoSize = true, Padding = new Padding(8, 3, 8, 3), Margin = new Padding(4) };
        b.Click += async (s, e) => await RunFix(key);
        fixPanel.Controls.Add(b);
        fixBtns.Add((b, ar, en, key));
    }

    // ============================================================= language
    void ApplyLang()
    {
        bool ar = L.Ar;
        RightToLeft = ar ? RightToLeft.Yes : RightToLeft.No;
        RightToLeftLayout = ar;

        btnScan.Text = L.T("ابدأ الفحص", "Start scan");
        btnLang.Text = ar ? "English" : "عربي";
        btnSave.Text = L.T("حفظ التقرير", "Save report");
        lblAdapter.Text = L.T("الاتصال:", "Connection:");
        if (!scanning) lblStatus.Text = rep == null ? L.T("جاهز. اختر نوع الاتصال ثم اضغط \"ابدأ الفحص\".", "Ready. Pick the connection and press \"Start scan\".") : lblStatus.Text;

        tOv.Text = L.T("نظرة عامة", "Overview");
        tDev.Text = L.T("الأجهزة", "Devices");
        tDiag.Text = L.T("لماذا الشبكة بطيئة؟", "Why is it slow?");
        tSec.Text = L.T("الأمان والمخاطر", "Security & risks");
        tSol.Text = L.T("الحلول والتسريع", "Fixes & speed-up");

        foreach (var c in CardDefs) cardTitle[c.key].Text = L.T(c.ar, c.en);
        foreach (var f in fixBtns) f.b.Text = L.T(f.ar, f.en);

        string[] devAr = { "IP", "الاسم", "MAC", "النوع", "الشركة", "Ping", "المنافذ المفتوحة", "ملاحظات" };
        string[] devEn = { "IP", "Name", "MAC", "Type", "Vendor", "Ping", "Open ports", "Notes" };
        for (int i = 0; i < gDev.Columns.Count; i++) gDev.Columns[i].HeaderText = ar ? devAr[i] : devEn[i];
        foreach (var g in new[] { gDiag, gSec })
        {
            g.Columns["sev"].HeaderText = L.T("الخطورة", "Severity");
            g.Columns["title"].HeaderText = L.T("المشكلة", "Issue");
            g.Columns["detail"].HeaderText = L.T("التفاصيل", "Details");
            g.Columns["fix"].HeaderText = L.T("الحل", "Solution");
        }
        gDev.RightToLeft = gDiag.RightToLeft = gSec.RightToLeft = RightToLeft;
        rtbSummary.RightToLeft = rtbSol.RightToLeft = RightToLeft;

        // refresh the adapter combo text (ToString depends on language)
        int sel = cmb.SelectedIndex;
        cmb.RightToLeft = RightToLeft.No;
        var items = cmb.Items.Cast<object>().ToArray();
        cmb.Items.Clear();
        cmb.Items.AddRange(items);
        if (sel >= 0 && sel < cmb.Items.Count) cmb.SelectedIndex = sel;

        if (rep != null)
        {
            foreach (var d in rep.Devices) Scanner.Classify(d);
            Render();
        }
        else RenderSolutionsIntro();
    }

    // ============================================================= adapters
    void LoadAdapters()
    {
        string keep = (cmb.SelectedItem as AdapterData)?.Id;
        cmb.Items.Clear();
        var list = NetInfo.GetAdapters();
        foreach (var a in list) cmb.Items.Add(a);
        var primary = NetInfo.PickPrimary(list);
        int idx = -1;
        for (int i = 0; i < cmb.Items.Count; i++)
        {
            var a = (AdapterData)cmb.Items[i];
            if (keep != null ? a.Id == keep : a == primary) { idx = i; break; }
        }
        if (idx < 0 && cmb.Items.Count > 0) idx = 0;
        if (idx >= 0) cmb.SelectedIndex = idx;
    }

    // ================================================================= scan
    async Task RunScan()
    {
        if (scanning) return;
        scanning = true;
        btnScan.Enabled = false;
        cmb.Enabled = false;
        bar.Visible = true;
        try
        {
            LoadAdapters();
            var sel = cmb.SelectedItem as AdapterData;
            if (sel == null)
            {
                MessageBox.Show(L.T("لا يوجد اتصال شبكة نشط. وصّل الكابل أو اتصل بالواي فاي ثم أعد المحاولة.",
                                    "No active network connection. Plug in the cable or join Wi-Fi and try again."),
                    "Network Scan", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                return;
            }

            var r = new Report { Adapter = sel };
            r.AllAdapters = cmb.Items.Cast<AdapterData>().ToList();

            Status(L.T("قراءة بيانات الاتصال...", "Reading connection details..."));
            if (sel.IsWifi)
            {
                Status(L.T("قياس قوة الواي فاي والشبكات المجاورة...", "Measuring Wi-Fi strength and nearby networks..."));
                r.Wifi = await Task.Run(NetInfo.GetWifi);
            }

            Status(L.T("قياس الاستهلاك في الخلفية...", "Measuring background traffic..."));
            r.BackgroundMbps = await NetInfo.BackgroundMbps(sel.Id);

            Status(L.T("قياس الـ Ping وفقد الحزم وDNS...", "Measuring ping, packet loss and DNS..."));
            var gwTask = sel.Gateway != null ? Scanner.PingStats(sel.Gateway) : Task.FromResult((-1.0, 0.0, 0.0));
            var netTask = Scanner.PingStats("1.1.1.1");
            var net2Task = Scanner.PingStats("8.8.8.8");
            var dnsTask = Scanner.DnsTime();
            await Task.WhenAll(gwTask, netTask, net2Task, dnsTask);
            (r.GwAvg, r.GwJitter, r.GwLoss) = gwTask.Result;
            var n1 = netTask.Result; var n2 = net2Task.Result;
            r.InternetOk = n1.loss < 100 || n2.loss < 100;
            var best = n1.loss < 100 && (n2.loss >= 100 || n1.avg <= n2.avg) ? n1 : n2;
            r.NetAvg = best.avg; r.NetJitter = best.jitter; r.NetLoss = Math.Min(n1.loss, n2.loss);
            r.DnsMs = dnsTask.Result;

            if (r.InternetOk)
            {
                Status(L.T("اختبار سرعة التحميل (8 ثوانٍ)...", "Testing download speed (8 s)..."));
                r.DownMbps = await Scanner.Download(8);
                Status(L.T("اختبار سرعة الرفع...", "Testing upload speed..."));
                r.UpMbps = await Scanner.Upload();
            }

            r.Devices = await Scanner.ScanDevices(sel, Status);

            Status(L.T("فحص الأمان (UPnP / الجدار الناري / البروكسي)...", "Security checks (UPnP / firewall / proxy)..."));
            r.UpnpOnGateway = await Scanner.UpnpOnGateway(sel);
            r.FirewallOff = await Task.Run(Scanner.FirewallOff);
            r.ProxyOn = Scanner.ProxyOn();

            Analyzer.Build(r);
            rep = r;
            Render();
            tabs.SelectedTab = tOv;
            Status(L.T("اكتمل الفحص ", "Scan complete ") + DateTime.Now.ToString("HH:mm:ss"));
        }
        catch (Exception ex)
        {
            Status(L.T("حدث خطأ: ", "Error: ") + ex.Message);
        }
        finally
        {
            scanning = false;
            btnScan.Enabled = true;
            cmb.Enabled = true;
            bar.Visible = false;
        }
    }

    void Status(string s) { lblStatus.Text = s; lblStatus.Refresh(); }

    // ============================================================== render
    static Color SevColor(string s) => s switch
    {
        "high" => Color.FromArgb(255, 205, 205),
        "med" => Color.FromArgb(255, 230, 190),
        "low" => Color.FromArgb(255, 250, 205),
        _ => Color.FromArgb(210, 240, 210)
    };

    static string SevText(string s) => s switch
    {
        "high" => L.T("عالية", "High"),
        "med" => L.T("متوسطة", "Medium"),
        "low" => L.T("منخفضة", "Low"),
        _ => L.T("سليم", "OK")
    };

    static string ScoreText(int s) =>
        $"{s}/100 — " + (s >= 80 ? L.T("ممتاز", "Excellent") : s >= 60 ? L.T("مقبول", "Fair") : L.T("ضعيف", "Poor"));

    static Color ScoreColor(int s) => s >= 80 ? Color.SeaGreen : s >= 60 ? Color.DarkOrange : Color.Firebrick;

    void Render()
    {
        var r = rep;
        var a = r.Adapter;
        bool wifi = a.IsWifi;

        cardValue["type"].Text = wifi ? "Wi-Fi" : L.T("كابل (Ethernet)", "Cable (Ethernet)");
        cardValue["adapter"].Text = a.Name;
        cardValue["ip"].Text = $"{a.Ip} / {a.Gateway ?? "-"}";
        if (wifi && r.Wifi != null)
        {
            int dbm = r.Wifi.SignalPct / 2 - 100;
            cardValue["link"].Text = $"{r.Wifi.SignalPct}% ({dbm} dBm)";
        }
        else cardValue["link"].Text = a.SpeedMbps > 0 ? $"{a.SpeedMbps:F0} Mbps" : "—";
        cardValue["down"].Text = r.InternetOk ? $"{r.DownMbps:F1} Mbps" : "—";
        cardValue["up"].Text = r.InternetOk ? $"{r.UpMbps:F1} Mbps" : "—";
        cardValue["ping"].Text = r.NetAvg >= 0 ? $"{r.NetAvg:F0} ms / {r.NetJitter:F0} ms" : "—";
        cardValue["loss"].Text = $"{r.NetLoss:F0}%";
        cardValue["dns"].Text = $"{r.DnsMs:F0} ms";
        cardValue["devices"].Text = r.Devices.Count.ToString();
        cardValue["perf"].Text = ScoreText(r.PerfScore);
        cardValue["perf"].ForeColor = ScoreColor(r.PerfScore);
        cardValue["sec"].Text = ScoreText(r.SecScore);
        cardValue["sec"].ForeColor = ScoreColor(r.SecScore);

        // summary
        rtbSummary.Clear();
        Append(rtbSummary, L.T("الخلاصة\n", "Summary\n"), true, 14);
        var top = r.Findings.Where(f => f.Cat == "perf" && f.Sev != "ok").OrderBy(f => f.Rank).Take(4).ToList();
        if (top.Count == 0)
            Append(rtbSummary, L.T("✔ لا يوجد سبب واضح للبطء من جهتك.\n", "✔ No clear cause of slowness on your side.\n"), false, 11);
        else
        {
            Append(rtbSummary, L.T("أهم أسباب البطء:\n", "Main causes of slowness:\n"), true, 11);
            foreach (var f in top) Append(rtbSummary, $"• {f.Title}\n   {f.Detail}\n", false, 11);
        }
        var secTop = r.Findings.Where(f => f.Cat == "sec" && f.Sev != "ok").OrderBy(f => f.Rank).Take(3).ToList();
        Append(rtbSummary, L.T("\nأهم المخاطر الأمنية:\n", "\nTop security risks:\n"), true, 11);
        if (secTop.Count == 0) Append(rtbSummary, L.T("✔ لا توجد مخاطر واضحة.\n", "✔ No obvious risks.\n"), false, 11);
        foreach (var f in secTop) Append(rtbSummary, $"• {f.Title}\n", false, 11);
        Append(rtbSummary, L.T("\nراجع تبويب \"الحلول والتسريع\" لخطوات الإصلاح.", "\nSee the \"Fixes & speed-up\" tab for the repair steps."), false, 10);

        // devices
        gDev.Rows.Clear();
        foreach (var d in r.Devices)
        {
            int i = gDev.Rows.Add(d.Ip,
                string.IsNullOrEmpty(d.Host) ? "-" : d.Host,
                d.Mac, d.Type, d.Vendor,
                d.PingMs >= 0 ? d.PingMs + " ms" : "-",
                d.OpenPorts.Count > 0 ? string.Join(", ", d.OpenPorts) : "-",
                d.Notes);
            var row = gDev.Rows[i];
            if (d.IsMe) row.DefaultCellStyle.BackColor = Color.FromArgb(225, 240, 255);
            else if (d.IsGateway) row.DefaultCellStyle.BackColor = Color.FromArgb(230, 245, 230);
            if (d.OpenPorts.Contains(23) || d.OpenPorts.Contains(21))
                row.DefaultCellStyle.ForeColor = Color.Firebrick;
        }

        FillFindings(gDiag, "perf");
        FillFindings(gSec, "sec");

        // solutions
        rtbSol.Clear();
        Append(rtbSol, L.T("الحلول مرتبة حسب الأولوية\n\n", "Fixes in priority order\n\n"), true, 14);
        int n = 1;
        foreach (var f in r.Findings.Where(x => x.Sev != "ok").OrderBy(x => x.Rank))
        {
            Append(rtbSol, $"{n++}. {f.Title}\n", true, 11);
            Append(rtbSol, $"   {f.Fix}\n\n", false, 11);
        }
        if (n == 1) Append(rtbSol, L.T("✔ لا توجد مشاكل تحتاج إصلاحاً.\n\n", "✔ Nothing needs fixing.\n\n"), false, 11);
        AppendTips();
    }

    void FillFindings(DataGridView g, string cat)
    {
        g.Rows.Clear();
        foreach (var f in rep.Findings.Where(x => x.Cat == cat).OrderBy(x => x.Rank))
        {
            int i = g.Rows.Add(SevText(f.Sev), f.Title, f.Detail, f.Fix);
            g.Rows[i].Cells[0].Style.BackColor = SevColor(f.Sev);
            g.Rows[i].Cells[0].Style.Font = new Font(g.Font, FontStyle.Bold);
        }
    }

    void RenderSolutionsIntro()
    {
        rtbSol.Clear();
        Append(rtbSol, L.T("نصائح عامة لتسريع الإنترنت\n\n", "General tips to speed up the internet\n\n"), true, 14);
        AppendTips();
    }

    void AppendTips()
    {
        Append(rtbSol, L.T("نصائح عامة لتسريع الشبكة\n", "General speed-up tips\n"), true, 12);
        string[] ar =
        {
            "استخدم كابل Cat6 بدل الواي فاي للكمبيوتر والتلفزيون والـ PlayStation.",
            "ضع الراوتر في مكان مرتفع ومركزي بعيداً عن الميكروويف والحوائط السميكة.",
            "استخدم نطاق 5GHz للأجهزة القريبة و2.4GHz للبعيدة.",
            "أعد تشغيل الراوتر والمودم مرة كل أسبوع أو عند البطء.",
            "حدّث فيرموير الراوتر وتعريف كرت الشبكة.",
            "غيّر DNS إلى 1.1.1.1 أو 8.8.8.8.",
            "أوقف تحديثات ويندوز والتورنت والمزامنة السحابية وقت العمل.",
            "فعّل QoS في الراوتر لإعطاء أولوية للمكالمات والألعاب.",
            "افصل الأجهزة غير المعروفة وغيّر كلمة سر الواي فاي إن شككت.",
            "اختبر الإنترنت من الكابل مباشرة بجانب المودم؛ إن كان بطيئاً فالمشكلة من الشركة.",
        };
        string[] en =
        {
            "Use a Cat6 cable instead of Wi-Fi for PC, TV and consoles.",
            "Put the router high and central, away from microwaves and thick walls.",
            "Use 5 GHz for nearby devices and 2.4 GHz for distant ones.",
            "Restart the router/modem weekly or whenever it slows down.",
            "Update router firmware and the network adapter driver.",
            "Switch DNS to 1.1.1.1 or 8.8.8.8.",
            "Pause Windows Update, torrents and cloud sync while working.",
            "Enable QoS on the router to prioritise calls and games.",
            "Remove unknown devices and change the Wi-Fi password if suspicious.",
            "Test with a cable right next to the modem; if still slow, the ISP is the cause.",
        };
        var tips = L.Ar ? ar : en;
        foreach (var t in tips) Append(rtbSol, "• " + t + "\n", false, 11);
    }

    static void Append(RichTextBox box, string text, bool bold, float size)
    {
        box.SelectionStart = box.TextLength;
        box.SelectionLength = 0;
        box.SelectionFont = new Font("Segoe UI", size, bold ? FontStyle.Bold : FontStyle.Regular);
        box.AppendText(text);
    }

    // ================================================================ fixes
    async Task RunFix(string key)
    {
        var sel = cmb.SelectedItem as AdapterData;
        bool needsAdapter = key is "cf" or "google" or "dnsauto";
        if (needsAdapter && sel == null)
        {
            MessageBox.Show(L.T("اختر الاتصال أولاً.", "Pick a connection first."), "Network Scan");
            return;
        }
        bool needsAdmin = key is "cf" or "google" or "dnsauto" or "renew" or "reset" or "perf" or "flush";
        if (needsAdmin && !Sys.IsAdmin())
        {
            MessageBox.Show(L.T("هذا الإجراء يحتاج صلاحيات المدير. أغلق البرنامج وشغّله بزر الماوس الأيمن ← تشغيل كمسؤول.",
                                "This action needs administrator rights. Close the app and run it via right-click → Run as administrator."),
                "Network Scan", MessageBoxButtons.OK, MessageBoxIcon.Information);
            return;
        }
        if (key == "reset" && MessageBox.Show(
                L.T("سيتم إعادة ضبط Winsock وTCP/IP وستحتاج لإعادة تشغيل الجهاز. هل تريد المتابعة؟",
                    "This resets Winsock and TCP/IP and requires a reboot. Continue?"),
                "Network Scan", MessageBoxButtons.YesNo, MessageBoxIcon.Question) != DialogResult.Yes) return;

        Status(L.T("جاري التنفيذ...", "Working..."));
        string name = sel?.Name ?? "";
        string output = await Task.Run(() =>
        {
            var sb = new StringBuilder();
            switch (key)
            {
                case "flush": sb.Append(Sys.Run("ipconfig", "/flushdns")); break;
                case "cf":
                    sb.Append(Sys.Run("netsh", $"interface ip set dns name=\"{name}\" static 1.1.1.1 primary"));
                    sb.Append(Sys.Run("netsh", $"interface ip add dns name=\"{name}\" 1.0.0.1 index=2"));
                    sb.Append(Sys.Run("ipconfig", "/flushdns"));
                    break;
                case "google":
                    sb.Append(Sys.Run("netsh", $"interface ip set dns name=\"{name}\" static 8.8.8.8 primary"));
                    sb.Append(Sys.Run("netsh", $"interface ip add dns name=\"{name}\" 8.8.4.4 index=2"));
                    sb.Append(Sys.Run("ipconfig", "/flushdns"));
                    break;
                case "dnsauto":
                    sb.Append(Sys.Run("netsh", $"interface ip set dns name=\"{name}\" dhcp"));
                    sb.Append(Sys.Run("ipconfig", "/flushdns"));
                    break;
                case "renew": sb.Append(Sys.Run("ipconfig", "/renew", 40000)); break;
                case "perf": sb.Append(Sys.Run("powercfg", "/setactive SCHEME_MIN")); break;
                case "reset":
                    sb.Append(Sys.Run("netsh", "winsock reset"));
                    sb.Append(Sys.Run("netsh", "int ip reset"));
                    break;
            }
            return sb.ToString().Trim();
        });
        Status(L.T("تم التنفيذ.", "Done."));
        MessageBox.Show(L.T("تم تنفيذ الإجراء.", "Action completed.") + (output.Length > 0 ? "\n\n" + Trunc(output, 600) : ""),
            "Network Scan", MessageBoxButtons.OK, MessageBoxIcon.Information);
    }

    static string Trunc(string s, int n) => s.Length <= n ? s : s.Substring(0, n) + "...";

    // ================================================================= save
    void SaveReport()
    {
        if (rep == null)
        {
            MessageBox.Show(L.T("نفّذ الفحص أولاً.", "Run a scan first."), "Network Scan");
            return;
        }
        using var dlg = new SaveFileDialog
        {
            Filter = "Text (*.txt)|*.txt",
            FileName = $"NetworkScan_{DateTime.Now:yyyyMMdd_HHmm}.txt"
        };
        if (dlg.ShowDialog() == DialogResult.OK)
        {
            File.WriteAllText(dlg.FileName, Analyzer.BuildText(rep), new UTF8Encoding(true));
            Status(L.T("تم حفظ التقرير.", "Report saved."));
        }
    }
}
