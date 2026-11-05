using System.Net;
using System.Net.NetworkInformation;
using System.Runtime.InteropServices;

namespace ZapretHub;

internal static class AiNetwork
{
    private static long _generation = 1, _next;
    private static string _fingerprint = "";
    private static readonly object Sync = new();
    static AiNetwork()
    {
        NetworkChange.NetworkAddressChanged += (_, _) => Changed();
        NetworkChange.NetworkAvailabilityChanged += (_, _) => Changed();
    }
    // Windows notifications are hints: DNS/NRPT updates and duplicate notifications
    // must not invalidate every successful probe when the actual route is unchanged.
    internal static void Changed() { Volatile.Write(ref _next, 0); }
    internal static void ForceChangeForTest() { Interlocked.Increment(ref _generation); Volatile.Write(ref _next, 0); }
    internal static string StableSet(IEnumerable<string> values) => string.Join(',', values.OrderBy(x => x, StringComparer.Ordinal));
    internal static long Generation
    {
        get
        {
            lock (Sync) if (Environment.TickCount64 >= _next)
            {
                _next = Environment.TickCount64 + 3000;
                try
                {
                    var parts = NetworkInterface.GetAllNetworkInterfaces().Where(n => n.OperationalStatus == OperationalStatus.Up).Select(n =>
                    {
                        var p=n.GetIPProperties();
                        return n.Id + ":" + StableSet(p.UnicastAddresses.Select(a=>a.Address.ToString())) + ":" + StableSet(p.GatewayAddresses.Select(a=>a.Address.ToString())) + ":" + StableSet(p.DnsAddresses.Select(a=>a.ToString()));
                    });
                    // Route-only changes need not raise NetworkAddressChanged.
                    string next = StableSet(parts) + "#" + StableSet(RouteKeys());
                    if (_fingerprint.Length > 0 && next != _fingerprint) Interlocked.Increment(ref _generation);
                    _fingerprint = next;
                }
                catch { }
            }
            return Interlocked.Read(ref _generation);
        }
    }
    [StructLayout(LayoutKind.Explicit, Size=28)] private struct Address
    { [FieldOffset(0)] internal ushort Family; [FieldOffset(4)] internal uint IPv4; }
    [StructLayout(LayoutKind.Explicit, Size=104)] private struct Route
    { [FieldOffset(8)] internal uint Index; [FieldOffset(44)] internal Address NextHop; [FieldOffset(84)] internal uint Metric; }
    [DllImport("iphlpapi.dll")] private static extern uint GetBestRoute2(IntPtr luid, uint index, IntPtr source, ref Address destination, uint options, out Route route, out Address bestSource);
    private static readonly string[] Destinations = { "31.31.207.68", "179.254.166.171", "162.159.36.5", "181.215.40.49", "179.254.166.174" };
    private static IEnumerable<string> RouteKeys()
    {
        foreach(var ip in Destinations)
        {
            var dest = new Address { Family=2, IPv4=BitConverter.ToUInt32(IPAddress.Parse(ip).GetAddressBytes()) };
            if(GetBestRoute2(IntPtr.Zero,0,IntPtr.Zero,ref dest,0,out var route,out var source)==0)
                yield return ip+":"+route.Index+":"+route.NextHop.IPv4+":"+source.IPv4;
        }
    }
    internal static object Snapshot()
    {
        var up = NetworkInterface.GetAllNetworkInterfaces().Where(n => n.OperationalStatus == OperationalStatus.Up).ToArray();
        var routes = new List<object>();
        foreach (string ip in Destinations)
        {
            try
            {
                var destination = new Address { Family = 2, IPv4 = BitConverter.ToUInt32(IPAddress.Parse(ip).GetAddressBytes()) };
                if (GetBestRoute2(IntPtr.Zero, 0, IntPtr.Zero, ref destination, 0, out var route, out var source) != 0) continue;
                var nic = up.FirstOrDefault(n => n.GetIPProperties().GetIPv4Properties()?.Index == route.Index);
                routes.Add(new { destination = ip, index = route.Index, metric = route.Metric, source = new IPAddress(BitConverter.GetBytes(source.IPv4)).ToString(), gateway = new IPAddress(BitConverter.GetBytes(route.NextHop.IPv4)).ToString(), adapter = nic?.Name, type = nic?.Description, tunnel = nic is not null && IsTunnel(nic) });
            }
            catch { }
        }
        return new { generation = Generation, utc = DateTime.UtcNow, routes, interfaces = up.Select(n => new { name=n.Name, description=n.Description, tunnel=IsTunnel(n), ipv6=n.GetIPProperties().UnicastAddresses.Any(a => a.Address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6 && !a.Address.IsIPv6LinkLocal && !IPAddress.IsLoopback(a.Address)) }).ToArray(), note = "Маршрут выбран Windows GetBestRoute2. WFP/WinDivert может дополнительно менять поток. VPN и SIMPLE FAKE автоматически не отключаются." };
    }
    internal static bool IsTunnel(NetworkInterface n) => n.NetworkInterfaceType is NetworkInterfaceType.Tunnel or NetworkInterfaceType.Ppp || new[] { "wintun", "wireguard", "tap-", "vpn", "outline", "amnezia" }.Any(s => (n.Description + n.Name).Contains(s, StringComparison.OrdinalIgnoreCase));
    internal static object SafeSnapshot(long? generation = null) => new { generation = generation ?? Generation, tunnelHint = NetworkInterface.GetAllNetworkInterfaces().Any(n => n.OperationalStatus == OperationalStatus.Up && IsTunnel(n)), route = "Внутренние IP, имена интерфейсов и шлюзы исключены из экспорта", filter = "Влияние SIMPLE FAKE/WFP не установлено" };
}
