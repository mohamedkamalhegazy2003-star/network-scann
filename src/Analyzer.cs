using System.Text;

namespace NetworkScan;

public static class Analyzer
{
    static void Add(Report r, string cat, string sev, string tAr, string tEn, string dAr, string dEn, string fAr, string fEn)
    {
        r.Findings.Add(new Finding
        {
            Cat = cat, Sev = sev,
            TAr = tAr, TEn = tEn, DAr = dAr, DEn = dEn, FAr = fAr, FEn = fEn
        });
    }

    public static void Build(Report r)
    {
        r.Findings.Clear();
        Performance(r);
        Security(r);

        r.PerfScore = Score(r, "perf");
        r.SecScore = Score(r, "sec");
    }

    static int Score(Report r, string cat)
    {
        int s = 100;
        foreach (var f in r.Findings.Where(x => x.Cat == cat))
            s -= f.Sev == "high" ? 25 : f.Sev == "med" ? 12 : f.Sev == "low" ? 4 : 0;
        return Math.Clamp(s, 0, 100);
    }

    // =====================================================================
    static void Performance(Report r)
    {
        var a = r.Adapter;
        var w = r.Wifi;
        bool wifi = a.IsWifi;

        if (!r.InternetOk)
        {
            Add(r, "perf", "high",
                "لا يوجد اتصال بالإنترنت", "No internet connection",
                "الجهاز متصل بالشبكة المحلية لكن لا يصل للإنترنت (فشل الاتصال بـ 1.1.1.1 و 8.8.8.8).",
                "The device is on the local network but cannot reach the internet (1.1.1.1 and 8.8.8.8 both failed).",
                "أعد تشغيل الراوتر والمودم (افصل الكهرباء 30 ثانية)، وتأكد من كابل الخط، ثم اتصل بشركة الإنترنت إن استمرت المشكلة.",
                "Restart the router/modem (unplug 30 s), check the line cable, and call your ISP if it persists.");
        }

        // ----- Local hop: PC -> router -----
        if (r.GwAvg >= 0)
        {
            if (r.GwLoss > 5)
            {
                Add(r, "perf", "high",
                    "فقد حزم بين جهازك والراوتر", "Packet loss between your PC and the router",
                    $"نسبة فقد الحزم إلى الراوتر {r.GwLoss:F0}% — المشكلة داخل شبكتك المحلية وليست من شركة الإنترنت.",
                    $"{r.GwLoss:F0}% of packets to the router are lost — the problem is inside your local network, not the ISP.",
                    wifi ? "قرّب جهازك من الراوتر أو غيّر قناة الواي فاي أو استخدم 5GHz، والأفضل التوصيل بكابل."
                         : "غيّر كابل الإيثرنت وجرّب منفذاً آخر في الراوتر، وحدّث تعريف كرت الشبكة.",
                    wifi ? "Move closer to the router, change the Wi-Fi channel, use 5 GHz — or better, use a cable."
                         : "Replace the Ethernet cable, try another router port and update the network driver.");
            }
            else if (r.GwAvg > (wifi ? 15 : 5))
            {
                Add(r, "perf", "med",
                    "زمن الاستجابة للراوتر مرتفع", "High latency to the router",
                    $"متوسط الاستجابة للراوتر {r.GwAvg:F0}ms (الطبيعي أقل من {(wifi ? 10 : 2)}ms).",
                    $"Average latency to the router is {r.GwAvg:F0} ms (normal is under {(wifi ? 10 : 2)} ms).",
                    wifi ? "ازدحام أو ضعف في الواي فاي: قلّل المسافة والعوائق وجرّب 5GHz أو كابل."
                         : "تحقق من الكابل (يفضّل Cat5e/Cat6) ومن أي سويتش وسيط، وأعد تشغيل الراوتر.",
                    wifi ? "Wi-Fi congestion/weakness: reduce distance and obstacles, try 5 GHz or a cable."
                         : "Check the cable (Cat5e/Cat6 recommended) and any intermediate switch; restart the router.");
            }
        }

        // ----- Internet hop -----
        if (r.InternetOk)
        {
            if (r.NetLoss > 2)
                Add(r, "perf", "high",
                    "فقد حزم في الاتصال بالإنترنت", "Packet loss on the internet link",
                    $"فقد الحزم نحو الإنترنت {r.NetLoss:F0}% (يسبب تقطيع المكالمات والألعاب وبطء التصفح).",
                    $"{r.NetLoss:F0}% packet loss towards the internet (causes call/game drops and slow pages).",
                    "إذا كان الفقد صفراً نحو الراوتر فالمشكلة من الخط أو شركة الإنترنت: أعد تشغيل المودم ثم اتصل بالشركة.",
                    "If loss to the router is zero, the line/ISP is at fault: restart the modem, then call the ISP.");
            if (r.NetAvg > 120)
                Add(r, "perf", "med",
                    "زمن استجابة الإنترنت عالٍ", "High internet latency",
                    $"متوسط الـ Ping للإنترنت {r.NetAvg:F0}ms.", $"Average internet ping is {r.NetAvg:F0} ms.",
                    "جرّب في وقت آخر، وأوقف التحميلات، وإذا استمر فاطلب من الشركة فحص الخط.",
                    "Try at another time, pause downloads, and ask the ISP to check the line if it persists.");
            else if (r.NetAvg > 60)
                Add(r, "perf", "low",
                    "زمن استجابة الإنترنت متوسط", "Moderate internet latency",
                    $"متوسط الـ Ping {r.NetAvg:F0}ms — مناسب للتصفح لكن قد يزعج في الألعاب.",
                    $"Average ping is {r.NetAvg:F0} ms — fine for browsing, noticeable in games.",
                    "استخدم كابل بدل الواي فاي وأوقف التحميلات أثناء اللعب.",
                    "Use a cable instead of Wi-Fi and pause downloads while gaming.");
            if (r.NetJitter > 30)
                Add(r, "perf", "med",
                    "تذبذب في زمن الاستجابة (Jitter)", "Unstable latency (jitter)",
                    $"التذبذب {r.NetJitter:F0}ms — يسبب تقطيع الصوت والفيديو.",
                    $"Jitter is {r.NetJitter:F0} ms — causes choppy audio/video.",
                    "قلّل عدد الأجهزة المستهلكة، فعّل QoS في الراوتر، وفضّل الكابل.",
                    "Reduce heavy devices, enable QoS on the router and prefer a cable.");
        }

        // ----- DNS -----
        if (r.DnsMs > 120)
            Add(r, "perf", "med",
                "خادم DNS بطيء", "Slow DNS server",
                $"متوسط زمن الـ DNS {r.DnsMs:F0}ms — يبطّئ فتح المواقع حتى لو كانت السرعة جيدة.",
                $"Average DNS lookup is {r.DnsMs:F0} ms — slows page loads even with good bandwidth.",
                "غيّر الـ DNS إلى 1.1.1.1 أو 8.8.8.8 (زر \"تغيير DNS\" في تبويب الحلول).",
                "Switch DNS to 1.1.1.1 or 8.8.8.8 (\"Change DNS\" button in the Solutions tab).");

        // ----- Cable-specific -----
        if (!wifi)
        {
            if (a.SpeedMbps > 0 && a.SpeedMbps <= 10)
                Add(r, "perf", "high",
                    "الكابل يعمل بسرعة 10Mbps فقط", "Cable link is only 10 Mbps",
                    "سرعة وصلة الإيثرنت 10Mbps — غالباً كابل تالف أو سلك ناقص أو منفذ معطوب.",
                    "Ethernet link speed is 10 Mbps — usually a damaged cable, broken pair or bad port.",
                    "استبدل الكابل بـ Cat5e/Cat6 سليم وجرّب منفذاً آخر في الراوتر.",
                    "Replace with a good Cat5e/Cat6 cable and try another router port.");
            else if (a.SpeedMbps > 0 && a.SpeedMbps <= 100)
                Add(r, "perf", "med",
                    "الكابل يعمل بسرعة 100Mbps فقط", "Cable link is only 100 Mbps",
                    "الوصلة 100Mbps بدل 1000Mbps (Gigabit) — لن تتجاوز السرعة ~94Mbps مهما كان اشتراكك.",
                    "The link negotiated 100 Mbps instead of 1 Gbps — throughput cannot exceed ~94 Mbps whatever your plan.",
                    "غالباً الكابل قديم (Cat5) أو فيه سلك مقطوع، أو الراوتر/السويتش Fast Ethernet. استبدل الكابل وتحقق من الراوتر.",
                    "Likely an old (Cat5) or partly broken cable, or a Fast-Ethernet router/switch. Replace the cable and check the router.");

            long pkts = a.PktsIn + a.PktsOut + 1;
            long errs = a.ErrIn + a.ErrOut;
            if (errs > 50 && errs * 100.0 / pkts > 0.5)
                Add(r, "perf", "high",
                    "أخطاء كثيرة على كرت الشبكة (الكابل)", "Many errors on the network card (cable)",
                    $"أخطاء الحزم {errs} من {pkts} ({errs * 100.0 / pkts:F2}%) — علامة كلاسيكية لكابل أو فيشة تالفة.",
                    $"{errs} packet errors out of {pkts} ({errs * 100.0 / pkts:F2}%) — classic sign of a bad cable or connector.",
                    "غيّر الكابل، ابعده عن كابلات الكهرباء، وجرّب منفذاً آخر.",
                    "Replace the cable, keep it away from power cables and try another port.");
            long disc = a.DiscIn + a.DiscOut;
            if (disc > 200 && disc * 100.0 / pkts > 1)
                Add(r, "perf", "low",
                    "حزم مُهملة على كرت الشبكة", "Discarded packets on the network card",
                    $"{disc} حزمة مُهملة — قد يدل على ازدحام أو مشكلة في التعريف.",
                    $"{disc} discarded packets — may indicate congestion or a driver issue.",
                    "حدّث تعريف كرت الشبكة من موقع الشركة المصنّعة.",
                    "Update the network adapter driver from the vendor's site.");
        }

        // ----- Wi-Fi-specific -----
        if (wifi && w != null)
        {
            if (w.SignalPct > 0)
            {
                if (w.SignalPct < 35)
                    Add(r, "perf", "high", "إشارة الواي فاي ضعيفة جداً", "Very weak Wi-Fi signal",
                        $"قوة الإشارة {w.SignalPct}% — هذا أهم سبب للبطء والانقطاع.",
                        $"Signal strength is {w.SignalPct}% — the main cause of slowness and drops.",
                        "قرّب من الراوتر أو انقل الراوتر لمكان مرتفع ومفتوح، أو أضف Repeater/Mesh، أو استخدم كابل.",
                        "Move closer, put the router higher and in the open, add a repeater/mesh node, or use a cable.");
                else if (w.SignalPct < 60)
                    Add(r, "perf", "med", "إشارة الواي فاي متوسطة", "Fair Wi-Fi signal",
                        $"قوة الإشارة {w.SignalPct}% — قد تقل السرعة عند الازدحام.",
                        $"Signal strength is {w.SignalPct}% — speed may drop under load.",
                        "قلّل العوائق (حوائط/أجهزة) بين الجهاز والراوتر أو استخدم 5GHz من مسافة قريبة.",
                        "Reduce obstacles (walls/appliances) or use 5 GHz at close range.");
            }

            bool is24 = (w.Band ?? "").Contains("2.4") || (w.Channel > 0 && w.Channel <= 14);
            if (is24 && w.SignalPct >= 60)
                Add(r, "perf", "low", "متصل على نطاق 2.4GHz", "Connected on the 2.4 GHz band",
                    "نطاق 2.4GHz أبطأ وأكثر ازدحاماً (ميكروويف، بلوتوث، جيران).",
                    "2.4 GHz is slower and more crowded (microwaves, Bluetooth, neighbours).",
                    "اتصل بشبكة 5GHz إن وُجدت (غالباً باسم الشبكة + 5G).",
                    "Join the 5 GHz network if available (often named with a 5G suffix).");

            if (!string.IsNullOrEmpty(w.Radio) && System.Text.RegularExpressions.Regex.IsMatch(w.Radio, @"802\.11(b|g|n)\b"))
                Add(r, "perf", "low", "معيار واي فاي قديم", "Old Wi-Fi standard",
                    $"الاتصال بمعيار {w.Radio} — أبطأ من 802.11ac/ax.",
                    $"Connected using {w.Radio} — slower than 802.11ac/ax.",
                    "فعّل 802.11ac/ax في الراوتر أو حدّث تعريف الكرت، وفكّر في راوتر أحدث.",
                    "Enable 802.11ac/ax on the router, update the driver, or consider a newer router.");

            if (w.Channel > 0 && w.Neighbors.Count > 0)
            {
                var others = w.Neighbors.Where(n => !string.Equals(n.Bssid, w.Bssid, StringComparison.OrdinalIgnoreCase)).ToList();
                Func<WifiNet, bool> overlaps = n => w.Channel <= 14 ? Math.Abs(n.Channel - w.Channel) <= 3 && n.Channel <= 14
                                                                    : n.Channel == w.Channel;
                int overlap = others.Count(overlaps);
                if (overlap >= 4)
                {
                    string best = BestChannel(others);
                    Add(r, "perf", "med", "ازدحام على قناة الواي فاي", "Wi-Fi channel congestion",
                        $"{overlap} شبكة مجاورة تتداخل مع قناتك ({w.Channel}) — تسبب بطء وتقطيع.",
                        $"{overlap} nearby networks overlap your channel ({w.Channel}) — causing slowness and drops.",
                        w.Channel <= 14 ? $"من إعدادات الراوتر غيّر القناة إلى {best} (الأفضل 1 أو 6 أو 11) أو انتقل لـ 5GHz."
                                        : "غيّر القناة من إعدادات الراوتر لقناة أقل ازدحاماً.",
                        w.Channel <= 14 ? $"In the router settings change the channel to {best} (1, 6 or 11 are best) or move to 5 GHz."
                                        : "Change to a less crowded channel in the router settings.");
                }
                else if (overlap >= 2)
                    Add(r, "perf", "low", "تداخل بسيط في القناة", "Mild channel overlap",
                        $"{overlap} شبكات مجاورة على قناة قريبة من قناتك ({w.Channel}).",
                        $"{overlap} nearby networks on channels close to yours ({w.Channel}).",
                        "جرّب قناة مختلفة من إعدادات الراوتر.", "Try a different channel in the router settings.");
            }
        }

        // ----- Throughput -----
        double reference = wifi ? (r.Wifi?.RxRate ?? 0) : a.SpeedMbps;
        if (r.InternetOk)
        {
            if (r.DownMbps < 3)
                Add(r, "perf", "high", "سرعة التحميل ضعيفة جداً", "Very low download speed",
                    $"سرعة التحميل الفعلية {r.DownMbps:F1}Mbps.", $"Measured download speed is {r.DownMbps:F1} Mbps.",
                    "افحص الاشتراك والخط مع شركة الإنترنت، وأوقف أي تحميلات، وأعد تشغيل المودم.",
                    "Check your plan/line with the ISP, pause downloads and restart the modem.");
            else if (r.DownMbps < 10)
                Add(r, "perf", "med", "سرعة التحميل منخفضة", "Low download speed",
                    $"سرعة التحميل {r.DownMbps:F1}Mbps — تكفي للتصفح فقط.", $"Download is {r.DownMbps:F1} Mbps — fine for browsing only.",
                    "قارن بالسرعة المشترك بها. إن كانت أقل بكثير فاتصل بالشركة.",
                    "Compare with your subscribed speed; if much lower, contact the ISP.");
            else if (reference > 0 && r.DownMbps < reference * 0.25 && r.DownMbps < 100)
                Add(r, "perf", "med", "السرعة الفعلية أقل بكثير من سرعة الوصلة", "Real speed far below link speed",
                    $"وصلتك {reference:F0}Mbps لكن الإنترنت الفعلي {r.DownMbps:F1}Mbps — عنق الزجاجة في الاشتراك أو الراوتر وليس في جهازك.",
                    $"Your link is {reference:F0} Mbps but internet throughput is {r.DownMbps:F1} Mbps — the bottleneck is the plan/router, not your PC.",
                    "قارن مع باقة الإنترنت، وأعد تشغيل الراوتر، وتحقق من أجهزة أخرى تستهلك الباندويث.",
                    "Compare with your plan, restart the router, and look for other devices hogging bandwidth.");
            if (r.UpMbps > 0 && r.UpMbps < 1)
                Add(r, "perf", "med", "سرعة الرفع ضعيفة", "Low upload speed",
                    $"سرعة الرفع {r.UpMbps:F1}Mbps — تؤثر على المكالمات المرئية ورفع الملفات.",
                    $"Upload is {r.UpMbps:F1} Mbps — affects video calls and file uploads.",
                    "أوقف النسخ الاحتياطي السحابي والرفع التلقائي وقت الاستخدام.",
                    "Pause cloud backups/auto-uploads while you work.");
        }

        if (r.BackgroundMbps > Math.Max(2, r.DownMbps * 0.2) && r.BackgroundMbps > 2)
            Add(r, "perf", "med", "جهازك يستهلك الإنترنت في الخلفية", "Your PC is using bandwidth in the background",
                $"قبل الفحص كان الجهاز يحمّل بمعدل {r.BackgroundMbps:F1}Mbps (تحديثات ويندوز، تورنت، مزامنة سحابية...).",
                $"Before the test the PC was downloading at {r.BackgroundMbps:F1} Mbps (Windows Update, torrents, cloud sync...).",
                "افتح مدير المهام ← تبويب الأداء/العمليات ← الشبكة، وأوقف البرنامج الذي يستهلك.",
                "Open Task Manager → Processes → Network and stop the heavy program.");

        if (r.Devices.Count >= 25)
            Add(r, "perf", "med", "عدد أجهزة كبير على الشبكة", "Many devices on the network",
                $"يوجد {r.Devices.Count} جهازاً متصلاً — قد يزدحم الراوتر.",
                $"{r.Devices.Count} devices are connected — the router may be overloaded.",
                "افصل الأجهزة غير المستخدمة، وفعّل QoS، أو استخدم راوتر أقوى.",
                "Disconnect unused devices, enable QoS or use a stronger router.");

        if (r.AllAdapters.Count(x => x.Gateway != null) > 1)
            Add(r, "perf", "low", "أكثر من اتصال نشط (كابل + واي فاي)", "More than one active connection (cable + Wi-Fi)",
                "ويندوز يختار اتصالاً واحداً حسب الأولوية وقد لا يكون الأسرع.",
                "Windows picks one by priority, which may not be the fastest.",
                "اترك الكابل فقط، أو أوقف الواي فاي عند استخدام الكابل.",
                "Keep only the cable, or turn Wi-Fi off while using the cable.");

        if (!r.Findings.Any(f => f.Cat == "perf" && f.Sev != "ok"))
            Add(r, "perf", "ok", "الأداء سليم", "Performance looks healthy",
                "لم يتم رصد أي سبب واضح للبطء من جهتك.",
                "No clear cause of slowness was found on your side.",
                "إذا كنت تشعر بالبطء في موقع بعينه فالمشكلة غالباً من الموقع نفسه.",
                "If only one site feels slow, the problem is likely on that site's side.");
    }

    static string BestChannel(List<WifiNet> others)
    {
        int bestCh = 1, bestCount = int.MaxValue;
        foreach (var ch in new[] { 1, 6, 11 })
        {
            int c = others.Count(n => n.Channel > 0 && n.Channel <= 14 && Math.Abs(n.Channel - ch) <= 3);
            if (c < bestCount) { bestCount = c; bestCh = ch; }
        }
        return bestCh.ToString();
    }

    // =====================================================================
    static void Security(Report r)
    {
        var a = r.Adapter;
        var w = r.Wifi;

        if (a.IsWifi && w != null && !string.IsNullOrEmpty(w.Auth))
        {
            string au = w.Auth.ToUpperInvariant();
            string ci = (w.Cipher ?? "").ToUpperInvariant();
            if (au.Contains("OPEN") && !au.Contains("OWE"))
                Add(r, "sec", "high", "شبكة الواي فاي بدون كلمة سر", "Wi-Fi network is open (no password)",
                    "أي شخص قريب يمكنه الاتصال ومراقبة بياناتك.", "Anyone nearby can join and snoop on your traffic.",
                    "فعّل WPA2 أو WPA3 مع كلمة سر قوية (12 حرفاً فأكثر) من إعدادات الراوتر.",
                    "Enable WPA2/WPA3 with a strong password (12+ characters) in the router settings.");
            else if (au.Contains("WEP"))
                Add(r, "sec", "high", "تشفير WEP قابل للكسر في دقائق", "WEP encryption can be cracked in minutes",
                    "WEP قديم وغير آمن.", "WEP is obsolete and insecure.",
                    "غيّر التشفير إلى WPA2-AES أو WPA3 فوراً.", "Switch to WPA2-AES or WPA3 immediately.");
            else if (au.Contains("WPA3"))
                Add(r, "sec", "ok", "تشفير الواي فاي ممتاز (WPA3)", "Wi-Fi encryption is excellent (WPA3)",
                    $"نوع الحماية: {w.Auth}.", $"Security type: {w.Auth}.", "لا إجراء مطلوب.", "No action needed.");
            else if (au.Contains("WPA2"))
            {
                if (ci.Contains("TKIP"))
                    Add(r, "sec", "med", "تشفير TKIP أضعف من AES", "TKIP cipher is weaker than AES",
                        $"الحماية {w.Auth} مع {w.Cipher}.", $"Security {w.Auth} with {w.Cipher}.",
                        "اختر WPA2-AES (CCMP) فقط من إعدادات الراوتر.", "Choose WPA2-AES (CCMP) only in the router settings.");
                else
                    Add(r, "sec", "ok", "تشفير الواي فاي جيد (WPA2)", "Wi-Fi encryption is good (WPA2)",
                        $"نوع الحماية: {w.Auth}.", $"Security type: {w.Auth}.",
                        "استخدم كلمة سر طويلة وغيّرها دورياً، وفكّر في WPA3 إن كان الراوتر يدعمه.",
                        "Use a long password, change it periodically and consider WPA3 if supported.");
            }
            else if (au.Contains("WPA"))
                Add(r, "sec", "high", "تشفير WPA الأول ضعيف", "Original WPA is weak",
                    $"الحماية {w.Auth}.", $"Security {w.Auth}.",
                    "انتقل إلى WPA2-AES أو WPA3.", "Move to WPA2-AES or WPA3.");
        }

        if (a.Gateway != null)
        {
            var gw = r.Devices.FirstOrDefault(d => d.IsGateway);
            if (gw != null)
            {
                if (gw.OpenPorts.Contains(23))
                    Add(r, "sec", "high", "الراوتر يفتح Telnet", "Router exposes Telnet",
                        "Telnet بلا تشفير ويُستغل في اختراق الراوترات.", "Telnet is unencrypted and widely abused to hijack routers.",
                        "عطّل Telnet من إعدادات الراوتر وغيّر كلمة المدير.", "Disable Telnet in the router and change the admin password.");
                if (gw.OpenPorts.Contains(21))
                    Add(r, "sec", "med", "الراوتر يفتح FTP", "Router exposes FTP",
                        "خدمة FTP على الراوتر غير ضرورية وغير مشفّرة.", "FTP on a router is unnecessary and unencrypted.",
                        "عطّل مشاركة الملفات/FTP في الراوتر.", "Disable file sharing/FTP on the router.");
                if (gw.OpenPorts.Contains(80) && !gw.OpenPorts.Contains(443))
                    Add(r, "sec", "low", "لوحة تحكم الراوتر عبر HTTP بدون تشفير", "Router admin page is plain HTTP",
                        "كلمة سر الراوتر تنتقل بدون تشفير داخل الشبكة.", "The router password travels unencrypted inside your LAN.",
                        "غيّر كلمة سر المدير الافتراضية وفعّل HTTPS للإدارة إن وُجد.", "Change the default admin password and enable HTTPS management if available.");
            }
            if (r.UpnpOnGateway)
                Add(r, "sec", "med", "UPnP مفعّل على الراوتر", "UPnP is enabled on the router",
                    "UPnP يسمح لأي برنامج على الشبكة بفتح منافذ للإنترنت دون علمك.", "UPnP lets any program open internet-facing ports without asking you.",
                    "عطّل UPnP من الراوتر إلا إذا كنت تحتاجه لألعاب أو برامج معينة.", "Disable UPnP unless a game/app needs it.");
        }

        foreach (var d in r.Devices.Where(x => !x.IsGateway))
        {
            string who = $"{d.Ip}" + (string.IsNullOrEmpty(d.Host) ? "" : $" ({d.Host})");
            if (d.OpenPorts.Contains(23))
                Add(r, "sec", "high", $"منفذ Telnet مفتوح على {who}", $"Telnet port open on {who}",
                    "خدمة غير مشفّرة وخطيرة.", "Unencrypted and dangerous service.",
                    "أوقف خدمة Telnet على هذا الجهاز.", "Disable the Telnet service on this device.");
            if (d.OpenPorts.Contains(21))
                Add(r, "sec", "med", $"منفذ FTP مفتوح على {who}", $"FTP port open on {who}",
                    "FTP ينقل كلمات السر بدون تشفير.", "FTP sends passwords in clear text.",
                    "استخدم SFTP أو أغلق الخدمة.", "Use SFTP or close the service.");
            if (d.OpenPorts.Contains(3389) && !d.IsMe)
                Add(r, "sec", "med", $"سطح المكتب البعيد (RDP) مفتوح على {who}", $"Remote Desktop (RDP) open on {who}",
                    "RDP هدف رئيسي لهجمات كلمات السر والفدية.", "RDP is a prime target for password attacks and ransomware.",
                    "عطّله إن لم تحتجه، أو فعّل NLA وكلمة سر قوية ولا تفتحه على الإنترنت.",
                    "Disable it if unused, or require NLA and a strong password and never expose it to the internet.");
            if (d.OpenPorts.Contains(5900))
                Add(r, "sec", "med", $"VNC مفتوح على {who}", $"VNC open on {who}",
                    "التحكم عن بعد بدون حماية كافية.", "Remote control with weak protection.",
                    "أغلق VNC أو ضع كلمة سر قوية وتشفير.", "Close VNC or enforce a strong password and encryption.");
            if (d.OpenPorts.Contains(554) && !d.IsMe)
                Add(r, "sec", "low", $"كاميرا/بث RTSP على {who}", $"RTSP camera/stream on {who}",
                    "تأكد أن الكاميرا ليست بكلمة المرور الافتراضية.", "Make sure the camera does not use its default password.",
                    "غيّر كلمة سر الكاميرا وحدّث برنامجها.", "Change the camera password and update its firmware.");
        }

        var dupMac = r.Devices.Where(d => !string.IsNullOrEmpty(d.Mac)).GroupBy(d => d.Mac).Where(g => g.Count() > 1).ToList();
        foreach (var g in dupMac)
            Add(r, "sec", "med", "نفس عنوان MAC لأكثر من IP", "Same MAC address for several IPs",
                $"العنوان {g.Key} ظاهر مع: {string.Join(", ", g.Select(x => x.Ip))}. قد يكون راوتر/Repeater طبيعي، وقد يكون هجوم ARP Spoofing.",
                $"MAC {g.Key} appears with: {string.Join(", ", g.Select(x => x.Ip))}. May be a normal repeater/router, or an ARP-spoofing attack.",
                "إن لم تكن تستخدم Repeater فأعد تشغيل الراوتر وافحص الأجهزة المشبوهة.",
                "If you do not use a repeater, restart the router and inspect the suspicious devices.");

        int unknown = r.Devices.Count(d => !d.IsMe && !d.IsGateway && d.Unknown);
        if (unknown > 0)
            Add(r, "sec", "low", $"{unknown} جهاز غير معروف", $"{unknown} unknown device(s)",
                "راجع قائمة الأجهزة وتأكد أنك تعرف كل جهاز.", "Review the device list and make sure you recognise each device.",
                "إذا وجدت جهازاً غريباً غيّر كلمة سر الواي فاي وفعّل تصفية MAC.",
                "If you find a stranger, change the Wi-Fi password and enable MAC filtering.");

        if (r.FirewallOff)
            Add(r, "sec", "high", "جدار حماية ويندوز مغلق", "Windows Firewall is off",
                "واحد أو أكثر من ملفات تعريف الجدار الناري معطّل.", "One or more firewall profiles are disabled.",
                "افتح Windows Security ← Firewall وفعّل كل الملفات.", "Open Windows Security → Firewall and turn all profiles on.");

        if (r.ProxyOn)
            Add(r, "sec", "low", "بروكسي مفعّل على الجهاز", "A proxy is enabled on this PC",
                "إذا لم تفعّله أنت فقد يكون برنامج مشبوه يمرّر حركتك.", "If you did not set it, a suspicious program may be routing your traffic.",
                "الإعدادات ← الشبكة والإنترنت ← Proxy وتأكد أنه مقصود.", "Settings → Network & Internet → Proxy and confirm it is intended.");

        if (!r.Findings.Any(f => f.Cat == "sec" && f.Sev != "ok"))
            Add(r, "sec", "ok", "لم يتم رصد مخاطر أمنية واضحة", "No obvious security risks found",
                "الفحص يغطي التشفير والمنافذ الشائعة وUPnP والجدار الناري.", "Scan covered encryption, common ports, UPnP and firewall.",
                "حدّث فيرموير الراوتر وعطّل WPS وغيّر كلمة المدير الافتراضية.",
                "Update router firmware, disable WPS and change the default admin password.");
    }

    // =====================================================================
    public static string BuildText(Report r)
    {
        var sb = new StringBuilder();
        sb.AppendLine("Network Scan — " + r.Time.ToString("yyyy-MM-dd HH:mm"));
        sb.AppendLine(new string('=', 50));
        sb.AppendLine($"{L.T("الاتصال", "Connection")}: {(r.Adapter.IsWifi ? "Wi-Fi" : L.T("كابل Ethernet", "Ethernet cable"))} — {r.Adapter.Name}");
        sb.AppendLine($"IP: {r.Adapter.Ip}   {L.T("الراوتر", "Gateway")}: {r.Adapter.Gateway}   DNS: {string.Join(", ", r.Adapter.Dns)}");
        if (r.Adapter.IsWifi && r.Wifi != null)
            sb.AppendLine($"Wi-Fi: {r.Wifi.Ssid}  {L.T("الإشارة", "Signal")} {r.Wifi.SignalPct}%  CH {r.Wifi.Channel}  {r.Wifi.Band}  {r.Wifi.Auth}");
        else
            sb.AppendLine($"{L.T("سرعة الوصلة", "Link speed")}: {r.Adapter.SpeedMbps:F0} Mbps");
        sb.AppendLine($"{L.T("تحميل", "Download")}: {r.DownMbps:F1} Mbps   {L.T("رفع", "Upload")}: {r.UpMbps:F1} Mbps   Ping: {r.NetAvg:F0} ms   {L.T("فقد", "Loss")}: {r.NetLoss:F0}%   DNS: {r.DnsMs:F0} ms");
        sb.AppendLine($"{L.T("تقييم الأداء", "Performance score")}: {r.PerfScore}/100   {L.T("تقييم الأمان", "Security score")}: {r.SecScore}/100");
        sb.AppendLine();
        sb.AppendLine(L.T("--- الأجهزة ---", "--- Devices ---"));
        foreach (var d in r.Devices)
            sb.AppendLine($"{d.Ip,-16} {d.Mac,-18} {d.Host,-25} {d.Type} {(d.OpenPorts.Count > 0 ? "[" + string.Join(",", d.OpenPorts) + "]" : "")}");
        sb.AppendLine();
        sb.AppendLine(L.T("--- النتائج والحلول ---", "--- Findings & fixes ---"));
        foreach (var f in r.Findings.OrderBy(x => x.Rank))
        {
            sb.AppendLine($"[{f.Sev.ToUpperInvariant()}] {f.Title}");
            sb.AppendLine("   " + f.Detail);
            sb.AppendLine("   → " + f.Fix);
        }
        return sb.ToString();
    }
}
