using System.Diagnostics;
using System.Net.NetworkInformation;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.RegularExpressions;

namespace SLHwid;

// §4A.1 factor collection per platform. The legacy slots reuse the shared
// composer's sources; the extended slots come from the registry,
// environment, native calls and best-effort subprocess queries. Every source
// degrades gracefully — a missing source just leaves the slot absent, which
// the threshold scheme absorbs.
internal static class SLHwidCollectors
{
    private const string DisplayClassGuid = "{4d36e968-e325-11ce-bfc1-08002be10318}";

    public static Dictionary<string, string> Collect()
    {
        if (OperatingSystem.IsWindows())
        {
            return CollectWindows();
        }
        if (OperatingSystem.IsMacOS())
        {
            return CollectDarwin();
        }
        if (OperatingSystem.IsLinux())
        {
            return CollectLinux();
        }
        throw new NotSupportedException("slhwid: secret-sharing HWID is not supported on this platform");
    }

    private static string MultiInstance(IEnumerable<string> values) =>
        string.Join("|", values.Where(v => v.Length > 0).Order());

    // ── Windows ────────────────────────────────────────────────────

    [System.Runtime.Versioning.SupportedOSPlatform("windows")]
    private static Dictionary<string, string> CollectWindows()
    {
        var factors = new Dictionary<string, string>();
        var bios = @"HARDWARE\DESCRIPTION\System\BIOS";

        Put(factors, "machine_guid", Registry(@"SOFTWARE\Microsoft\Cryptography", "MachineGuid"));
        Put(factors, "product_uuid", Registry(@"SYSTEM\CurrentControlSet\Control\SystemInformation", "ComputerHardwareId")?.Trim('{', '}'));
        Put(factors, "board_serial", Registry(bios, "BaseBoardSerialNumber"));
        Put(factors, "cpu_id", Registry(@"HARDWARE\DESCRIPTION\System\CentralProcessor\0", "Identifier"));
        Put(factors, "firmware", MultiInstance(new[]
        {
            Registry(bios, "SystemBiosVersion") ?? "",
            Registry(bios, "BIOSVersion") ?? "",
        }));
        if (Registry(@"SOFTWARE\Microsoft\Windows NT\CurrentVersion", "CurrentBuildNumber") is { } build
            && Registry(@"SOFTWARE\Microsoft\Windows NT\CurrentVersion", "UBR") is { } ubr
            && int.TryParse(ubr.TrimStart("0x".ToCharArray()), System.Globalization.NumberStyles.HexNumber, null, out var ubrValue))
        {
            factors["os_build"] = $"{build}-{ubrValue}";
        }
        Put(factors, "computer_name", Environment.GetEnvironmentVariable("COMPUTERNAME"));
        Put(factors, "gpu_id", MultiInstance(RegistrySubvalues(
            $@"SYSTEM\CurrentControlSet\Control\Class\{DisplayClassGuid}", "DriverDesc")));
        Put(factors, "monitor_edid", MultiInstance(RegistryEdidBlobs().Select(b => Convert.ToHexString(b).ToLowerInvariant())));
        Put(factors, "disk_serial", MultiInstance(WmicColumn("diskdrive", "SerialNumber")));
        Put(factors, "ram_total", RamTotal());
        Put(factors, "volume_id", VolumeSerial());
        Put(factors, "mac", MacAddress());
        return factors;
    }

    private static void Put(Dictionary<string, string> factors, string slot, string? value)
    {
        if (!string.IsNullOrEmpty(value))
        {
            factors[slot] = value;
        }
    }

    [System.Runtime.Versioning.SupportedOSPlatform("windows")]
    private static string? Registry(string path, string name)
    {
        try
        {
            using var root = Microsoft.Win32.RegistryKey.OpenBaseKey(
                Microsoft.Win32.RegistryHive.LocalMachine,
                Microsoft.Win32.RegistryView.Registry64);
            using var key = root.OpenSubKey(path);
            return key?.GetValue(name) switch
            {
                string s => s,
                string[] multi => string.Join(" ", multi),
                int i => $"0x{i:x}",
                _ => null,
            };
        }
        catch
        {
            return null;
        }
    }

    [System.Runtime.Versioning.SupportedOSPlatform("windows")]
    private static IEnumerable<string> RegistrySubvalues(string path, string name)
    {
        List<string> values = [];
        try
        {
            using var root = Microsoft.Win32.RegistryKey.OpenBaseKey(
                Microsoft.Win32.RegistryHive.LocalMachine,
                Microsoft.Win32.RegistryView.Registry64);
            using var parent = root.OpenSubKey(path);
            if (parent is not null)
            {
                foreach (var subkey in parent.GetSubKeyNames().Order())
                {
                    using var key = parent.OpenSubKey(subkey);
                    if (key?.GetValue(name) is string value)
                    {
                        values.Add(value);
                    }
                }
            }
        }
        catch
        {
            // degrade gracefully
        }
        return values;
    }

    [System.Runtime.Versioning.SupportedOSPlatform("windows")]
    private static IEnumerable<byte[]> RegistryEdidBlobs()
    {
        try
        {
            using var root = Microsoft.Win32.RegistryKey.OpenBaseKey(
                Microsoft.Win32.RegistryHive.LocalMachine,
                Microsoft.Win32.RegistryView.Registry64);
            using var display = root.OpenSubKey(@"SYSTEM\CurrentControlSet\Enum\DISPLAY");
            if (display is null)
            {
                return [];
            }
            var blobs = new List<byte[]>();
            foreach (var adapterName in display.GetSubKeyNames().Order())
            {
                using var adapter = display.OpenSubKey(adapterName);
                if (adapter is null)
                {
                    continue;
                }
                foreach (var instanceName in adapter.GetSubKeyNames().Order())
                {
                    using var parameters = adapter.OpenSubKey($"{instanceName}\\Device Parameters");
                    if (parameters?.GetValue("EDID") is byte[] blob)
                    {
                        blobs.Add(blob);
                    }
                }
            }
            return blobs;
        }
        catch
        {
            return [];
        }
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct MemoryStatusEx
    {
        public uint Length;
        public uint MemoryLoad;
        public ulong TotalPhys;
        public ulong AvailPhys;
        public ulong TotalPageFile;
        public ulong AvailPageFile;
        public ulong TotalVirtual;
        public ulong AvailVirtual;
        public ulong AvailExtendedVirtual;
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GlobalMemoryStatusEx(ref MemoryStatusEx status);

    [System.Runtime.Versioning.SupportedOSPlatform("windows")]
    private static string? RamTotal()
    {
        var status = new MemoryStatusEx { Length = (uint)Marshal.SizeOf<MemoryStatusEx>() };
        return GlobalMemoryStatusEx(ref status) ? status.TotalPhys.ToString() : null;
    }

    private static string? VolumeSerial()
    {
        var drive = Environment.GetEnvironmentVariable("SystemDrive") ?? "C:";
        var output = Run("cmd.exe", $"/c vol {drive}");
        var matches = Regex.Matches(output, "([0-9A-Fa-f]{4}-[0-9A-Fa-f]{4})");
        return matches.Count > 0 ? matches[^1].Value : null;
    }

    private static IEnumerable<string> WmicColumn(string entity, string column)
    {
        var output = Run("wmic.exe", $"{entity} get {column}");
        return output.Split('\n')
            .Select(line => line.Trim())
            .Where(line => line.Length > 0 && !string.Equals(line, column, StringComparison.OrdinalIgnoreCase));
    }

    private static string? MacAddress()
    {
        foreach (var iface in NetworkInterface.GetAllNetworkInterfaces())
        {
            if (iface.NetworkInterfaceType == NetworkInterfaceType.Loopback)
            {
                continue;
            }
            var name = iface.Name.ToLowerInvariant();
            if (new[] { "vethernet", "vmware", "virtual", "tap", "tun", "zerotier", "wsl", "docker", "bluetooth", "tailscale", "vpn" }.Any(name.StartsWith))
            {
                continue;
            }
            var mac = iface.GetPhysicalAddress().ToString();
            if (mac.Length == 12)
            {
                return mac;
            }
        }
        return null;
    }

    // ── macOS ──────────────────────────────────────────────────────

    private static Dictionary<string, string> CollectDarwin()
    {
        var factors = new Dictionary<string, string>();

        var expert = Run("ioreg", "-rd1 -c IOPlatformExpertDevice");
        Put(factors, "machine_guid", FirstMatch(expert, "\"IOPlatformUUID\"\\s*=\\s*\"([^\"]+)\""));
        Put(factors, "board_serial", FirstMatch(expert, "\"IOPlatformSerialNumber\"\\s*=\\s*\"([^\"]+)\""));

        var brand = Run("sysctl", "-n machdep.cpu.brand_string").Trim();
        if (brand.Length == 0)
        {
            brand = Run("sysctl", "-n hw.model").Trim();
        }
        var cores = Run("sysctl", "-n hw.physicalcpu").Trim();
        if (brand.Length > 0 && cores.Length > 0)
        {
            factors["cpu_id"] = $"{brand}-{cores}";
        }

        Put(factors, "mac", FirstMatch(Run("ifconfig", "en0"), "ether\\s+([0-9a-fA-F:]{17})"));
        Put(factors, "ram_total", Run("sysctl", "-n hw.memsize").Trim());
        Put(factors, "volume_id", FirstMatch(Run("diskutil", "info -plist /"), "<key>VolumeUUID</key>\\s*<string>([^<]+)</string>"));
        Put(factors, "computer_name", NullIfEmpty(Run("scutil", "--get ComputerName").Trim()) ?? NullIfEmpty(Run("scutil", "--get LocalHostName").Trim()));
        Put(factors, "firmware", FirstMatch(Run("system_profiler", "SPHardwareDataType -json", 5), "\"spmachine_bootrom_version\"\\s*:\\s*\"([^\"]+)\""));

        var displays = Run("system_profiler", "SPDisplaysDataType -json", 5);
        var models = AllMatches(displays, "\"spdisplays_model\"\\s*:\\s*\"([^\"]+)\"");
        if (models.Count > 0)
        {
            factors["gpu_id"] = string.Join("|", models.Order());
        }

        var storage = Run("system_profiler", "SPStorageDataType -json", 5);
        var serials = AllMatches(storage, "\"[a-z_]*serial[a-z_]*\"\\s*:\\s*\"([^\"]+)\"");
        if (serials.Count > 0)
        {
            factors["disk_serial"] = string.Join("|", serials.Order());
        }

        var displayIo = Run("ioreg", "-r -c IODisplayConnect");
        var blobs = AllMatches(displayIo, "\"IODisplayEDID\"\\s*=\\s*<?([0-9a-fA-F]+)>?");
        if (blobs.Count > 0)
        {
            factors["monitor_edid"] = string.Join("|", blobs.Select(b => b.ToLowerInvariant()).Order());
        }

        var version = Run("sw_vers", "-productVersion").Trim();
        var build = Run("sw_vers", "-buildVersion").Trim();
        if (version.Length > 0 && build.Length > 0)
        {
            factors["os_build"] = $"{version}-{build}";
        }

        if (factors.Count == 0)
        {
            throw new InvalidOperationException("slhwid: no hardware factors available on this machine");
        }
        return factors;
    }

    // ── Linux ──────────────────────────────────────────────────────

    private static Dictionary<string, string> CollectLinux()
    {
        var factors = new Dictionary<string, string>();
        foreach (var (slot, path) in new[]
        {
             ("machine_guid", "/etc/machine-id"),
             ("board_serial", "/sys/class/dmi/id/board_serial"),
             ("product_uuid", "/sys/class/dmi/id/product_uuid"),
             ("firmware", "/sys/class/dmi/id/bios_version"),
        })
        {
            Put(factors, slot, ReadTextFile(path));
        }
        {
            var cpuinfo = ReadTextFile("/proc/cpuinfo") ?? "";
            var match = Regex.Match(cpuinfo, @"Serial\s*:\s*([0-9a-f]+)");
            if (match.Success)
            {
                factors["cpu_id"] = match.Groups[1].Value;
            }
        }
        Put(factors, "disk_serial", ReadTextFile("/sys/block/sda/device/serial"));

        Put(factors, "computer_name", Environment.MachineName);
        try
        {
            var meminfo = File.ReadAllText("/proc/meminfo");
            var match = Regex.Match(meminfo, @"MemTotal:\s+(\d+)\s+kB");
            if (match.Success)
            {
                factors["ram_total"] = (long.Parse(match.Groups[1].Value) * 1024).ToString();
            }
        }
        catch
        {
            // absent
        }
        Put(factors, "volume_id", NullIfEmpty(Run("findmnt", "-no UUID /").Trim()));
        Put(factors, "firmware", ReadTextFile("/sys/class/dmi/id/bios_version"));
        try
        {
            var osRelease = File.ReadAllText("/etc/os-release");
            var match = Regex.Match(osRelease, "^PRETTY_NAME=\"?([^\"\\n]+)\"?", RegexOptions.Multiline);
            if (match.Success)
            {
                factors["os_build"] = match.Groups[1].Value;
            }
        }
        catch
        {
            // absent
        }

        var blobs = new List<string>();
        try
        {
            foreach (var dir in Directory.GetDirectories("/sys/class/drm").Order())
            {
                if (!Path.GetFileName(dir).StartsWith("card") || !Path.GetFileName(dir).Contains('-'))
                {
                    continue;
                }
                try
                {
                    var data = File.ReadAllBytes(Path.Join(dir, "edid"));
                    if (data.Length > 0)
                    {
                        blobs.Add(Convert.ToHexString(data).ToLowerInvariant());
                    }
                }
                catch
                {
                    // absent
                }
            }
        }
        catch
        {
            // absent
        }
        if (blobs.Count > 0)
        {
            factors["monitor_edid"] = string.Join("|", blobs.Order());
        }

        var gpus = new List<string>();
        try
        {
            foreach (var device in Directory.GetDirectories("/sys/bus/pci/devices").Order())
            {
                try
                {
                    var klass = File.ReadAllText(Path.Join(device, "class")).Trim();
                    if (!klass.StartsWith("0x03"))
                    {
                        continue;
                    }
                    var vendor = File.ReadAllText(Path.Join(device, "vendor")).Trim();
                    var id = File.ReadAllText(Path.Join(device, "device")).Trim();
                    gpus.Add($"{vendor}:{id}");
                }
                catch
                {
                    // absent
                }
            }
        }
        catch
        {
            // absent
        }
        if (gpus.Count > 0)
        {
            factors["gpu_id"] = string.Join("|", gpus.Order());
        }

        return factors;
    }

    // ── shared helpers ─────────────────────────────────────────────

    private static string? NullIfEmpty(string? value) =>
        string.IsNullOrEmpty(value) ? null : value;

    private static string? ReadTextFile(string path)
    {
        try
        {
            var value = File.ReadAllText(path).Trim();
            return value.Length > 0 ? value : null;
        }
        catch
        {
            return null;
        }
    }

    private static string Run(string fileName, string arguments, int timeoutSeconds = 4)
    {
        try
        {
            var info = new ProcessStartInfo
            {
                FileName = fileName,
                Arguments = arguments,
                RedirectStandardOutput = true,
                UseShellExecute = false,
                CreateNoWindow = true,
            };
            using var process = Process.Start(info);
            if (process is null)
            {
                return "";
            }
            using var cancellationTokenSource = new CancellationTokenSource(TimeSpan.FromSeconds(timeoutSeconds));
            if (!process.WaitForExit(timeoutSeconds * 1000))
            {
                try
                {
                    process.Kill(entireProcessTree: true);
                }
                catch
                {
                    // already gone
                }
                return "";
            }
            return process.StandardOutput.ReadToEnd();
        }
        catch
        {
            return "";
        }
    }

    private static string FirstMatch(string text, string pattern)
    {
        var match = Regex.Match(text, pattern);
        return match.Success ? match.Groups[1].Value : "";
    }

    private static List<string> AllMatches(string text, string pattern)
    {
        var results = new List<string>();
        foreach (Match match in Regex.Matches(text, pattern))
        {
            results.Add(match.Groups[1].Value);
        }
        return results;
    }
}
