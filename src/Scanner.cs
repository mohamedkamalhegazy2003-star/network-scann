using System.Collections.Concurrent;
using System.Diagnostics;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Text;
using System.Text.RegularExpressions;

namespace NetworkScan;

public static class Scanner
{
    // ---------- Latency / loss / jitter ----------
    public static async Task<(double avg, double jitter, double loss)> PingStats(string host, int n = 10)
    {
        var rtts = new List<long>();
        using var p = new Ping();
        for (int i = 0; i < n; i++)
        {
            try
            {
                var r = await p.SendAsync(host, 1000);
                if (r.Status == IPStatus.Success) rtts.Add(r.RoundtripTime);
            }
            catch { }
            await Task.Delay(100);
        }
        if (rtts.Count == 0) return (-1, 0, 100);
        double avg = rtts.Average();
        double jit = 0;
        for (int i = 1; i < rtts.Count; i++) jit += Math.Abs(rtts[i] - rtts[i - 1]);
        jit = rtts.Count > 1 ? jit / (rtts.Count - 1) : 0;
        return (avg, jit, (n - rtts.Count) * 100.0 / n);
    }

    public static async Task<double> DnsTime()
    {
        var times = new List<double>();
        for (int i = 0; i < 3; i++)
        {
            var sw = Stopwatch.StartNew();
            try { await Dns.GetHostEntryAsync(Guid.NewGuid().ToString("N").Substring(0, 12) + ".example.com"); }
            catch { }
            sw.Stop();
            times.Add(sw.Elapsed.TotalMilliseconds);
        }
        return times.Average();
    }

    // ---------- Speed ----------
    public static async Task<double> Download(int seconds = 8)
    {
        try
        {
            using var http = new HttpClient { Timeout = TimeSpan.FromSeconds(30) };
            var total = new long[1];
            using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(seconds));
            var sw = Stopwatch.StartNew();
            var tasks = Enumerable.Range(0, 4).Select(async _ =>
            {
                try
                {
                    while (!cts.IsCancellationRequested)
                    {
                        using var resp = await http.GetAsync("https://speed.cloudflare.com/__down?bytes=50000000",
                            HttpCompletionOption.ResponseHeadersRead, cts.Token);
                        using var s = await resp.Content.ReadAsStreamAsync(cts.Token);
                        var buf = new byte[65536];
                        int n;
                        while ((n = await s.ReadAsync(buf, 0, buf.Length, cts.Token)) > 0)
                            Interlocked.Add(ref total[0], n);
                    }
                }
                catch { }
            }).ToArray();
            await Task.WhenAll(tasks);
            sw.Stop();
            return total[0] * 8.0 / Math.Max(0.5, sw.Elapsed.TotalSeconds) / 1e6;
        }
        catch { return 0; }
    }

    public static async Task<double> Upload(int bytes = 8_000_000)
    {
        try
        {
            var data = new byte[bytes];
            new Random().NextBytes(data);
            using var http = new HttpClient { Timeout = TimeSpan.FromSeconds(40) };
            var sw = Stopwatch.StartNew();
            var r = await http.PostAsync("https://speed.cloudflare.com/__up", new ByteArrayContent(data));
            sw.Stop();
            if (!r.IsSuccessStatusCode) return 0;
            return bytes * 8.0 / sw.Elapsed.TotalSeconds / 1e6;
        }
        catch { return 0; }
    }

    // ---------- Devices ----------
    static uint ToUInt(IPAddress ip)
    {
        var b = ip.GetAddressBytes();
        return ((uint)b[0] << 24) | ((uint)b[1] << 16) | ((uint)b[2] << 8) | b[3];
    }

    static IPAddress FromUInt(uint v) =>
        new IPAddress(new[] { (byte)(v >> 24), (byte)(v >> 16), (byte)(v >> 8), (byte)v });

    static readonly int[] ProbePorts = { 21, 22, 23, 80, 135, 139, 443, 445, 554, 3389, 5900, 8080, 9100 };

    public static async Task<List<DeviceInfo>> ScanDevices(AdapterData a, Action<string> status)
    {
        uint ip = ToUInt(IPAddress.Parse(a.Ip));
        uint mask = ToUInt(IPAddress.Parse(a.Mask));
        // Never sweep more than a /24 (254 hosts)
        if (mask < 0xFFFFFF00u) mask = 0xFFFFFF00u;
        uint net = ip & mask;
        uint bcast = net | ~mask;

        var alive = new ConcurrentDictionary<string, long>();
        var sem = new SemaphoreSlim(100);
        status(L.T("جاري البحث عن الأجهزة على الشبكة...", "Looking for devices on the network..."));
        var pings = new List<Task>();
        for (uint h = net + 1; h < bcast; h++)
        {
            var target = FromUInt(h);
            pings.Add(Task.Run(async () =>
            {
                await sem.WaitAsync();
                try
                {
                    using var p = new Ping();
                    var r = await p.SendAsync(target, 700);
                    if (r.Status == IPStatus.Success) alive[target.ToString()] = r.RoundtripTime;
                }
                catch { }
                finally { sem.Release(); }
            }));
        }
        await Task.WhenAll(pings);

        // ARP table (also catches devices that block ping)
        var macs = new Dictionary<string, string>();
        string arp = await Task.Run(() => Sys.Run("arp", "-a"));
        foreach (Match m in Regex.Matches(arp, @"(\d+\.\d+\.\d+\.\d+)\s+([0-9a-fA-F]{2}(?:-[0-9a-fA-F]{2}){5})"))
        {
            string ipStr = m.Groups[1].Value;
            string mac = m.Groups[2].Value.ToUpperInvariant();
            if (!IPAddress.TryParse(ipStr, out var addr)) continue;
            uint u = ToUInt(addr);
            if ((u & mask) != net || u == bcast || u == net) continue;
            if (mac.StartsWith("FF-FF") || mac.StartsWith("01-00-5E")) continue;
            macs[ipStr] = mac;
        }

        var ips = new HashSet<string>(alive.Keys);
        foreach (var k in macs.Keys) ips.Add(k);
        ips.Add(a.Ip);

        var devices = ips.Select(i => new DeviceInfo
        {
            Ip = i,
            Mac = i == a.Ip ? a.Mac : (macs.TryGetValue(i, out var mm) ? mm : ""),
            PingMs = alive.TryGetValue(i, out var ms) ? ms : -1,
            IsMe = i == a.Ip,
            IsGateway = i == a.Gateway
        }).OrderBy(d => ToUInt(IPAddress.Parse(d.Ip))).ToList();

        status(L.T("جاري التعرف على أسماء الأجهزة ومنافذها...", "Identifying device names and open ports..."));
        var work = devices.Select(d => Task.Run(async () =>
        {
            d.Host = await Resolve(d.Ip);
            foreach (var port in ProbePorts)
                if (await IsOpen(d.Ip, port)) d.OpenPorts.Add(port);
            Classify(d);
        })).ToList();
        await Task.WhenAll(work);
        return devices;
    }

    static async Task<string> Resolve(string ip)
    {
        try
        {
            var t = Dns.GetHostEntryAsync(ip);
            if (await Task.WhenAny(t, Task.Delay(1500)) == t && t.IsCompletedSuccessfully)
                return t.Result.HostName ?? "";
        }
        catch { }
        return "";
    }

    static async Task<bool> IsOpen(string ip, int port, int ms = 450)
    {
        try
        {
            using var c = new TcpClient();
            var t = c.ConnectAsync(ip, port);
            if (await Task.WhenAny(t, Task.Delay(ms)) == t && t.IsCompletedSuccessfully) return c.Connected;
        }
        catch { }
        return false;
    }

    static readonly Dictionary<string, string> Oui = new()
    {
        ["B8-27-EB"] = "Raspberry Pi", ["DC-A6-32"] = "Raspberry Pi", ["E4-5F-01"] = "Raspberry Pi",
        ["00-50-56"] = "VMware", ["00-0C-29"] = "VMware", ["08-00-27"] = "VirtualBox", ["00-15-5D"] = "Microsoft Hyper-V",
        ["50-C7-BF"] = "TP-Link", ["F4-F2-6D"] = "TP-Link", ["98-DA-C4"] = "TP-Link",
        ["F4-F5-D8"] = "Google", ["3C-5A-B4"] = "Google", ["54-60-09"] = "Google",
        ["FC-A1-83"] = "Amazon", ["44-65-0D"] = "Amazon", ["00-E0-FC"] = "Huawei",
        ["F0-18-98"] = "Apple", ["3C-22-FB"] = "Apple", ["A4-83-E7"] = "Apple"
    };

    static bool Randomized(string mac)
    {
        if (string.IsNullOrEmpty(mac) || mac.Length < 2) return false;
        int first = Convert.ToInt32(mac.Substring(0, 2), 16);
        return (first & 0x02) != 0; // locally administered bit
    }

    public static void Classify(DeviceInfo d)
    {
        d.Unknown = false;
        d.Notes = "";
        string mac = d.Mac ?? "";
        if (mac.Length >= 8 && Oui.TryGetValue(mac.Substring(0, 8), out var v)) d.Vendor = v;
        bool rnd = Randomized(mac);
        string h = (d.Host ?? "").ToLowerInvariant();

        if (d.IsMe) d.Type = L.T("هذا الجهاز", "This PC");
        else if (d.IsGateway) d.Type = L.T("الراوتر", "Router");
        else if (Regex.IsMatch(h, "iphone|ipad|android|galaxy|redmi|xiaomi|huawei|oppo|realme|pixel|phone"))
            d.Type = L.T("موبايل / تابلت", "Phone / Tablet");
        else if (Regex.IsMatch(h, "tv|roku|bravia|chromecast|firestick|webos|tizen"))
            d.Type = L.T("تلفزيون / ستريمينج", "TV / Streaming");
        else if (Regex.IsMatch(h, "printer|epson|canon|brother|laserjet|officejet") || d.OpenPorts.Contains(9100))
            d.Type = L.T("طابعة", "Printer");
        else if (d.OpenPorts.Contains(554)) d.Type = L.T("كاميرا مراقبة (غالباً)", "IP camera (likely)");
        else if (d.OpenPorts.Contains(3389) || d.OpenPorts.Contains(445) || d.OpenPorts.Contains(135))
            d.Type = L.T("كمبيوتر ويندوز", "Windows PC");
        else if (d.Vendor == "Apple") d.Type = L.T("جهاز أبل", "Apple device");
        else if (rnd) d.Type = L.T("موبايل (عنوان MAC عشوائي)", "Phone (randomized MAC)");
        else { d.Type = L.T("غير معروف", "Unknown"); d.Unknown = true; }

        if (rnd && string.IsNullOrEmpty(d.Vendor))
            d.Notes = L.T("عنوان MAC خاص/عشوائي (طبيعي في الموبايلات الحديثة)", "Private/randomized MAC (normal on modern phones)");
    }

    // ---------- Security probes ----------
    /// <summary>Returns true if the router itself answers UPnP discovery.</summary>
    public static async Task<bool> UpnpOnGateway(AdapterData a)
    {
        if (a.Gateway == null) return false;
        try
        {
            using var udp = new UdpClient();
            udp.Client.Bind(new IPEndPoint(IPAddress.Parse(a.Ip), 0));
            string msg = "M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\nMX: 2\r\nST: ssdp:all\r\n\r\n";
            var bytes = Encoding.ASCII.GetBytes(msg);
            await udp.SendAsync(bytes, bytes.Length, "239.255.255.250", 1900);
            var end = DateTime.UtcNow.AddSeconds(3);
            while (DateTime.UtcNow < end)
            {
                var t = udp.ReceiveAsync();
                var left = end - DateTime.UtcNow;
                if (left <= TimeSpan.Zero) break;
                if (await Task.WhenAny(t, Task.Delay(left)) != t) break;
                if (t.IsCompletedSuccessfully && t.Result.RemoteEndPoint.Address.ToString() == a.Gateway) return true;
            }
        }
        catch { }
        return false;
    }

    public static bool FirewallOff()
    {
        string o = Sys.Run("powershell",
            "-NoProfile -Command \"(Get-NetFirewallProfile | ForEach-Object { $_.Enabled }) -join ','\"", 15000);
        return o.IndexOf("False", StringComparison.OrdinalIgnoreCase) >= 0;
    }

    public static bool ProxyOn()
    {
        try
        {
            using var k = Microsoft.Win32.Registry.CurrentUser.OpenSubKey(
                @"Software\Microsoft\Windows\CurrentVersion\Internet Settings");
            return k?.GetValue("ProxyEnable") is int i && i == 1;
        }
        catch { return false; }
    }
}
