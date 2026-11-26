using System.Diagnostics;
using System.Globalization;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Text;
using System.Text.RegularExpressions;

namespace NetworkScan;

public static class Sys
{
    static Encoding Oem()
    {
        try { return Encoding.GetEncoding(CultureInfo.CurrentCulture.TextInfo.OEMCodePage); }
        catch { return Encoding.UTF8; }
    }

    public static string Run(string file, string args, int timeoutMs = 20000)
    {
        try
        {
            var psi = new ProcessStartInfo(file, args)
            {
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                CreateNoWindow = true,
                StandardOutputEncoding = Oem()
            };
            using var p = Process.Start(psi);
            var t = p.StandardOutput.ReadToEndAsync();
            if (!p.WaitForExit(timeoutMs))
            {
                try { p.Kill(); } catch { }
            }
            return t.Wait(3000) ? t.Result : "";
        }
        catch { return ""; }
    }

    public static bool IsAdmin()
    {
        try
        {
            using var id = System.Security.Principal.WindowsIdentity.GetCurrent();
            return new System.Security.Principal.WindowsPrincipal(id)
                .IsInRole(System.Security.Principal.WindowsBuiltInRole.Administrator);
        }
        catch { return false; }
    }
}

public static class NetInfo
{
    static bool IsWired(NetworkInterfaceType t) =>
        t == NetworkInterfaceType.Ethernet || t == NetworkInterfaceType.GigabitEthernet ||
        t == NetworkInterfaceType.FastEthernetT || t == NetworkInterfaceType.FastEthernetFx ||
        t == NetworkInterfaceType.Ethernet3Megabit;

    public static List<AdapterData> GetAdapters()
    {
        var list = new List<AdapterData>();
        foreach (var ni in NetworkInterface.GetAllNetworkInterfaces())
        {
            if (ni.OperationalStatus != OperationalStatus.Up) continue;
            string kind = ni.NetworkInterfaceType == NetworkInterfaceType.Wireless80211 ? "wifi"
                        : IsWired(ni.NetworkInterfaceType) ? "wired" : "other";
            if (kind == "other") continue;

            string desc = ni.Description ?? "";
            if (Regex.IsMatch(desc, "virtual|vmware|hyper-v|vethernet|virtualbox|vpn|tap-|bluetooth|loopback|pseudo",
                    RegexOptions.IgnoreCase)) continue;

            var props = ni.GetIPProperties();
            var ua = props.UnicastAddresses.FirstOrDefault(a => a.Address.AddressFamily == AddressFamily.InterNetwork);
            if (ua == null) continue;
            if (ua.Address.ToString().StartsWith("169.254.")) continue; // no DHCP lease

            var gw = props.GatewayAddresses.FirstOrDefault(g =>
                g.Address.AddressFamily == AddressFamily.InterNetwork && !g.Address.Equals(IPAddress.Any));

            var a = new AdapterData
            {
                Id = ni.Id,
                Name = ni.Name,
                Desc = desc,
                Kind = kind,
                Mac = string.Join("-", ni.GetPhysicalAddress().GetAddressBytes().Select(b => b.ToString("X2"))),
                Ip = ua.Address.ToString(),
                Mask = ua.IPv4Mask?.ToString() ?? "255.255.255.0",
                Gateway = gw?.Address.ToString(),
                SpeedMbps = ni.Speed > 0 ? ni.Speed / 1_000_000.0 : 0
            };
            foreach (var d in props.DnsAddresses)
                if (d.AddressFamily == AddressFamily.InterNetwork) a.Dns.Add(d.ToString());

            try
            {
                var st = ni.GetIPv4Statistics();
                a.ErrIn = st.IncomingPacketsWithErrors;
                a.ErrOut = st.OutgoingPacketsWithErrors;
                a.DiscIn = st.IncomingPacketsDiscarded;
                a.DiscOut = st.OutgoingPacketsDiscarded;
                a.PktsIn = st.UnicastPacketsReceived + st.NonUnicastPacketsReceived;
                a.PktsOut = st.UnicastPacketsSent + st.NonUnicastPacketsSent;
            }
            catch { }
            list.Add(a);
        }
        return list;
    }

    public static AdapterData PickPrimary(List<AdapterData> list) =>
        list.Where(x => x.Gateway != null).OrderBy(x => x.Kind == "wired" ? 0 : 1).FirstOrDefault()
        ?? list.FirstOrDefault();

    /// <summary>Bytes received per second on the adapter, in Mbps, measured over a short window.</summary>
    public static async Task<double> BackgroundMbps(string id, int ms = 2000)
    {
        try
        {
            var ni = NetworkInterface.GetAllNetworkInterfaces().First(n => n.Id == id);
            long b1 = ni.GetIPv4Statistics().BytesReceived;
            await Task.Delay(ms);
            long b2 = NetworkInterface.GetAllNetworkInterfaces().First(n => n.Id == id).GetIPv4Statistics().BytesReceived;
            return Math.Max(0, (b2 - b1) * 8.0 / (ms / 1000.0) / 1e6);
        }
        catch { return 0; }
    }

    static readonly Regex Kv = new(@"^\s*([^:]+?)\s*:\s*(.*?)\s*$", RegexOptions.Compiled);

    public static WifiData GetWifi()
    {
        var w = new WifiData();
        string o = Sys.Run("netsh", "wlan show interfaces");
        var kv = new List<(string k, string v)>();
        foreach (var line in o.Split('\n'))
        {
            var m = Kv.Match(line.TrimEnd('\r'));
            if (m.Success) kv.Add((m.Groups[1].Value, m.Groups[2].Value));
        }
        if (kv.Count == 0) return w;

        string Get(Func<string, bool> pred) => kv.FirstOrDefault(x => pred(x.k)).v;
        w.Ssid = Get(k => k.Equals("SSID", StringComparison.OrdinalIgnoreCase));
        w.Bssid = Get(k => k.Equals("BSSID", StringComparison.OrdinalIgnoreCase));
        w.Radio = Get(k => k.StartsWith("Radio type", StringComparison.OrdinalIgnoreCase));
        w.Auth = Get(k => k.StartsWith("Authentication", StringComparison.OrdinalIgnoreCase));
        w.Cipher = Get(k => k.StartsWith("Cipher", StringComparison.OrdinalIgnoreCase));
        w.Band = Get(k => k.Equals("Band", StringComparison.OrdinalIgnoreCase));
        int.TryParse(Get(k => k.Equals("Channel", StringComparison.OrdinalIgnoreCase)), out w.Channel);
        double.TryParse(Regex.Match(Get(k => k.StartsWith("Receive rate", StringComparison.OrdinalIgnoreCase)) ?? "", @"[\d.]+").Value,
            NumberStyles.Any, CultureInfo.InvariantCulture, out w.RxRate);
        double.TryParse(Regex.Match(Get(k => k.StartsWith("Transmit rate", StringComparison.OrdinalIgnoreCase)) ?? "", @"[\d.]+").Value,
            NumberStyles.Any, CultureInfo.InvariantCulture, out w.TxRate);

        string sig = Get(k => k.Equals("Signal", StringComparison.OrdinalIgnoreCase));
        if (string.IsNullOrEmpty(sig)) sig = kv.Select(x => x.v).FirstOrDefault(v => Regex.IsMatch(v, @"^\d{1,3}%$")) ?? "";
        int.TryParse(sig.Replace("%", ""), out w.SignalPct);

        // Fallbacks for non-English Windows (labels are localized)
        if (string.IsNullOrEmpty(w.Auth))
            w.Auth = kv.Select(x => x.v).FirstOrDefault(v => Regex.IsMatch(v, @"WPA|WEP|Open|OWE", RegexOptions.IgnoreCase));
        if (string.IsNullOrEmpty(w.Radio))
            w.Radio = kv.Select(x => x.v).FirstOrDefault(v => v.StartsWith("802.11"));
        if (string.IsNullOrEmpty(w.Ssid) && kv.Count > 5) w.Ssid = kv[5].v;
        if (w.Channel == 0)
        {
            var ch = kv.Select(x => x.v).FirstOrDefault(v => Regex.IsMatch(v, @"^\d{1,3}$") && int.Parse(v) is >= 1 and <= 196);
            if (ch != null) w.Channel = int.Parse(ch);
        }
        if (string.IsNullOrEmpty(w.Band) && w.Channel > 0) w.Band = w.Channel <= 14 ? "2.4 GHz" : "5 GHz";

        w.Neighbors = GetNeighbors();
        return w;
    }

    static List<WifiNet> GetNeighbors()
    {
        var res = new List<WifiNet>();
        string o = Sys.Run("netsh", "wlan show networks mode=bssid", 25000);
        string ssid = "";
        WifiNet cur = null;
        foreach (var line in o.Split('\n'))
        {
            var m = Kv.Match(line.TrimEnd('\r'));
            if (!m.Success) continue;
            string k = m.Groups[1].Value, v = m.Groups[2].Value;
            if (Regex.IsMatch(k, @"^SSID\s*\d+", RegexOptions.IgnoreCase)) { ssid = v; cur = null; }
            else if (Regex.IsMatch(k, @"^BSSID\s*\d+", RegexOptions.IgnoreCase))
            {
                cur = new WifiNet { Ssid = ssid, Bssid = v };
                res.Add(cur);
            }
            else if (cur != null && k.Equals("Signal", StringComparison.OrdinalIgnoreCase))
                int.TryParse(v.Replace("%", ""), out cur.Signal);
            else if (cur != null && k.Equals("Channel", StringComparison.OrdinalIgnoreCase))
                int.TryParse(v, out cur.Channel);
        }
        return res;
    }
}
