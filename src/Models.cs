namespace NetworkScan;

public static class L
{
    public static bool Ar = true;
    public static string T(string ar, string en) => Ar ? ar : en;
}

public class AdapterData
{
    public string Id, Name, Desc, Kind, Mac, Ip, Mask, Gateway;
    public List<string> Dns = new();
    public double SpeedMbps;
    public long ErrIn, ErrOut, DiscIn, DiscOut, PktsIn, PktsOut;

    public bool IsWifi => Kind == "wifi";

    public override string ToString()
    {
        string k = Kind == "wifi" ? "Wi-Fi" : L.T("كابل", "Cable");
        return $"{Name} [{k}] - {Ip}";
    }
}

public class WifiNet
{
    public string Ssid, Bssid;
    public int Signal, Channel;
}

public class WifiData
{
    public string Ssid, Bssid, Auth, Cipher, Radio, Band;
    public int Channel, SignalPct;
    public double RxRate, TxRate;
    public List<WifiNet> Neighbors = new();
}

public class DeviceInfo
{
    public string Ip, Mac, Host = "", Vendor = "", Type = "", Notes = "";
    public bool IsGateway, IsMe, Unknown;
    public long PingMs = -1;
    public List<int> OpenPorts = new();
}

public class Finding
{
    public string Cat, Sev;      // Cat: perf | sec   Sev: high | med | low | ok
    public string TAr, TEn, DAr, DEn, FAr, FEn;
    public string Title => L.T(TAr, TEn);
    public string Detail => L.T(DAr, DEn);
    public string Fix => L.T(FAr, FEn);
    public int Rank => Sev == "high" ? 0 : Sev == "med" ? 1 : Sev == "low" ? 2 : 3;
}

public class Report
{
    public DateTime Time = DateTime.Now;
    public AdapterData Adapter;
    public List<AdapterData> AllAdapters = new();
    public WifiData Wifi;
    public List<DeviceInfo> Devices = new();

    public double DownMbps, UpMbps, BackgroundMbps;
    public double GwAvg = -1, GwJitter, GwLoss;
    public double NetAvg = -1, NetJitter, NetLoss;
    public double DnsMs;
    public bool InternetOk;

    public bool UpnpOnGateway;
    public bool FirewallOff;
    public bool ProxyOn;

    public List<Finding> Findings = new();
    public int PerfScore, SecScore;
}
