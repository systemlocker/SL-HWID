using System.Diagnostics;
using System.Net.NetworkInformation;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;

namespace SLHwid;

// SL-HWID factor collection per platform. The legacy slots reuse the shared
// composer's sources; the extended slots come from the registry,
// environment, native calls and best-effort subprocess queries. Every source
// degrades gracefully — a missing source just leaves the slot absent, which
// the threshold scheme absorbs.
internal static class SLHwidCollectors
{
    private const string DisplayClassGuid = "{4d36e968-e325-11ce-bfc1-08002be10318}";

    public static Dictionary<string, string> Collect() => Collect(null);

    internal static Dictionary<string, string> Collect(Action<string, string>? diagnostic)
    {
        if (OperatingSystem.IsWindows())
        {
            return CollectWindows(diagnostic);
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

    // Ordinal order matches the other implementations' byte-wise sort. The
    // default comparer follows the current culture, so the joined value could
    // change with the user's language settings.
    // Each member is trimmed of ASCII whitespace first (the C++ rule), so
    // padded firmware strings produce the same value in every implementation.
    private static string MultiInstance(IEnumerable<string> values) =>
        string.Join("|", values.Select(v => v.Trim(AsciiWhitespace)).Where(v => v.Length > 0).Order(StringComparer.Ordinal));

    private static readonly char[] AsciiWhitespace = [' ', '\t', '\n', '\v', '\f', '\r'];

    // ── Windows ────────────────────────────────────────────────────

    [System.Runtime.Versioning.SupportedOSPlatform("windows")]
    private static Dictionary<string, string> CollectWindows(Action<string, string>? diagnostic)
    {
        var factors = new Dictionary<string, string>();
        var bios = @"HARDWARE\DESCRIPTION\System\BIOS";

        Put(factors, "machine_guid", Registry(@"SOFTWARE\Microsoft\Cryptography", "MachineGuid"));
        var registryProductUuid = Registry(@"SYSTEM\CurrentControlSet\Control\SystemInformation", "ComputerHardwareId")?.Trim('{', '}');
        Put(factors, "product_uuid", registryProductUuid);
        // ComputerHardwareId is a Windows-derived hardware identifier, not the
        // SMBIOS UUID exposed by CIM. Read the UUID from raw SMBIOS so toggling
        // PowerShell/CIM availability cannot change the platform slot.
        Put(factors, "system_uuid", SystemUuid());
        Put(factors, "board_serial", Registry(bios, "BaseBoardSerialNumber"));
        Put(factors, "cpu_id", Registry(@"HARDWARE\DESCRIPTION\System\CentralProcessor\0", "Identifier"));
        Put(factors, "firmware", MultiInstance(new[]
        {
            Registry(bios, "SystemBiosVersion") ?? "",
            Registry(bios, "BIOSVersion") ?? "",
        }));
        // Registry() renders a DWORD as "0x<hex>". Strip only the prefix:
        // TrimStart('0', 'x') also removed the digit of UBR 0, dropping the value.
        if (Registry(@"SOFTWARE\Microsoft\Windows NT\CurrentVersion", "CurrentBuildNumber") is { } build
            && Registry(@"SOFTWARE\Microsoft\Windows NT\CurrentVersion", "UBR") is { } ubr
            && ubr.StartsWith("0x", StringComparison.Ordinal)
            && uint.TryParse(ubr.AsSpan(2), System.Globalization.NumberStyles.AllowHexSpecifier,
                System.Globalization.CultureInfo.InvariantCulture, out var ubrValue))
        {
            factors["os_build"] = $"{build}-{ubrValue}";
        }
        Put(factors, "computer_name", Environment.GetEnvironmentVariable("COMPUTERNAME"));
        Put(factors, "gpu_id", MultiInstance(RegistrySubvalues(
            $@"SYSTEM\CurrentControlSet\Control\Class\{DisplayClassGuid}", "DriverDesc")));
        Put(factors, "monitor_edid", MultiInstance(RegistryEdidBlobs().Select(b => Convert.ToHexString(b).ToLowerInvariant())));
        var disks = PhysicalDisks();
        Put(factors, "disk_serial", MultiInstance(disks.Select(disk => disk.Serial)));
        Put(factors, "fixed_disk_serial", MultiInstance(disks.Where(disk => IsFixedBus(disk.BusType)).Select(disk => disk.Serial)));
        Put(factors, "ram_total", RamTotal());
        Put(factors, "volume_id", VolumeSerial());
        Put(factors, "mac", MacAddress());
        var nativeTpm = SLHwidTpm.CollectNative(out var tpmDetail);
        Put(factors, "tpm_ek", nativeTpm);
        diagnostic?.Invoke("tpm_ek", tpmDetail);

        // Schema-v2 signals. The legacy signals above intentionally remain:
        // existing schema-v1 helpers still need their original values to recover.
        MergeWindowsFactors(factors, WindowsSchemaV2Factors(nativeTpm is null, diagnostic));
        return factors;
    }

    internal static void MergeWindowsFactors(Dictionary<string, string> factors, Dictionary<string, string> fallback)
    {
        foreach (var (name, value) in fallback)
        {
            // Native values define the cross-language representation. CIM is
            // strictly a fallback/enrichment source and must not overwrite a
            // value merely because PowerShell happened to work this launch.
            if (!factors.ContainsKey(name))
            {
                Put(factors, name, value);
            }
        }
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

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetVolumeInformation(
        string rootPathName,
        StringBuilder? volumeNameBuffer,
        int volumeNameSize,
        out uint volumeSerialNumber,
        out uint maximumComponentLength,
        out uint fileSystemFlags,
        StringBuilder? fileSystemNameBuffer,
        int fileSystemNameSize);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern nint CreateFile(
        string fileName,
        uint desiredAccess,
        uint shareMode,
        nint securityAttributes,
        uint creationDisposition,
        uint flagsAndAttributes,
        nint templateFile);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool DeviceIoControl(
        nint device,
        uint controlCode,
        byte[] input,
        uint inputSize,
        byte[] output,
        uint outputSize,
        out uint bytesReturned,
        nint overlapped);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CloseHandle(nint handle);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern uint GetSystemFirmwareTable(uint providerSignature, uint tableId, byte[]? buffer, uint bufferSize);

    private const uint IoctlStorageQueryProperty = 0x002D1400;
    private const uint RsmbProvider = 0x52534D42;
    private static readonly nint InvalidHandleValue = new(-1);

    [System.Runtime.Versioning.SupportedOSPlatform("windows")]
    private static string? SystemUuid()
    {
        var size = GetSystemFirmwareTable(RsmbProvider, 0, null, 0);
        if (size is < 8 or > 1024 * 1024)
        {
            return null;
        }
        var raw = new byte[checked((int)size)];
        return GetSystemFirmwareTable(RsmbProvider, 0, raw, size) == size
            ? ParseSystemUuid(raw)
            : null;
    }

    internal static string? ParseSystemUuid(byte[] raw)
    {
        if (raw.Length < 8)
        {
            return null;
        }
        var tableLength = BitConverter.ToUInt32(raw, 4);
        if (tableLength > raw.Length - 8)
        {
            return null;
        }
        var end = 8 + checked((int)tableLength);
        for (var offset = 8; offset + 4 <= end;)
        {
            var type = raw[offset];
            var formattedLength = raw[offset + 1];
            if (formattedLength < 4 || offset + formattedLength > end)
            {
                return null;
            }
            if (type == 1 && formattedLength >= 24)
            {
                var uuid = raw.AsSpan(offset + 8, 16);
                if (uuid.ToArray().All(b => b == 0) || uuid.ToArray().All(b => b == 0xff))
                {
                    return null;
                }
                var littleEndianFields = raw[1] > 2 || raw[1] == 2 && raw[2] >= 6;
                if (littleEndianFields)
                {
                    return new Guid(uuid).ToString("D");
                }
                return $"{Convert.ToHexString(uuid[..4])}-{Convert.ToHexString(uuid.Slice(4, 2))}-" +
                       $"{Convert.ToHexString(uuid.Slice(6, 2))}-{Convert.ToHexString(uuid.Slice(8, 2))}-" +
                       Convert.ToHexString(uuid[10..]);
            }
            var next = offset + formattedLength;
            while (next + 1 < end && (raw[next] != 0 || raw[next + 1] != 0))
            {
                next++;
            }
            if (next + 1 >= end)
            {
                return null;
            }
            offset = next + 2;
            if (type == 127)
            {
                break;
            }
        }
        return null;
    }

    // Schema v3 fixed disks: everything except USB (7), SD (12), MMC (13) and
    // mounted disk images (15, FileBackedVirtual). The values are Windows'
    // STORAGE_BUS_TYPE, which MSFT_PhysicalDisk.BusType reports identically.
    internal static bool IsFixedBus(uint busType) => busType is not (7 or 12 or 13 or 15);

    [System.Runtime.Versioning.SupportedOSPlatform("windows")]
    private static List<(string Serial, uint BusType)> PhysicalDisks()
    {
        var serials = new List<(string Serial, uint BusType)>();
        var query = new byte[12]; // StorageDeviceProperty + PropertyStandardQuery
        for (var index = 0; index < 32; index++)
        {
            var disk = CreateFile($@"\\.\PhysicalDrive{index}", 0, 3, 0, 3, 0, 0);
            if (disk == InvalidHandleValue)
            {
                continue;
            }
            try
            {
                var header = new byte[8];
                if (!DeviceIoControl(disk, IoctlStorageQueryProperty, query, (uint)query.Length,
                        header, (uint)header.Length, out _, 0))
                {
                    continue;
                }
                var descriptorSize = BitConverter.ToUInt32(header, 4);
                if (descriptorSize is < 36 or > 1024 * 1024)
                {
                    continue;
                }
                var descriptor = new byte[descriptorSize];
                if (!DeviceIoControl(disk, IoctlStorageQueryProperty, query, (uint)query.Length,
                        descriptor, descriptorSize, out var returned, 0))
                {
                    continue;
                }
                var serial = ParseStorageSerial(descriptor, returned);
                if (serial is not null)
                {
                    serials.Add((serial, ParseStorageBusType(descriptor, returned)));
                }
            }
            finally
            {
                CloseHandle(disk);
            }
        }
        return serials;
    }

    // STORAGE_DEVICE_DESCRIPTOR.BusType sits at byte 28. The serial parser
    // already requires the full 36-byte fixed header, so this read is in range.
    internal static uint ParseStorageBusType(byte[] descriptor, uint returned) =>
        returned >= 32 && descriptor.Length >= 32 ? BitConverter.ToUInt32(descriptor, 28) : 0;

    internal static string? ParseStorageSerial(byte[] descriptor, uint returned)
    {
        if (returned < 36 || returned > descriptor.Length)
        {
            return null;
        }
        var returnedLength = checked((int)returned);
        var offset = BitConverter.ToUInt32(descriptor, 24);
        if (offset == 0 || offset >= returned)
        {
            return null;
        }
        var end = (int)offset;
        while (end < returnedLength && descriptor[end] != 0)
        {
            end++;
        }
        var value = Encoding.ASCII.GetString(descriptor, (int)offset, end - (int)offset).Trim();
        return value.Length == 0 ? null : value;
    }

    [System.Runtime.Versioning.SupportedOSPlatform("windows")]
    private static string? RamTotal()
    {
        var status = new MemoryStatusEx { Length = (uint)Marshal.SizeOf<MemoryStatusEx>() };
        return GlobalMemoryStatusEx(ref status) ? status.TotalPhys.ToString() : null;
    }

    private static string? VolumeSerial()
    {
        var drive = Environment.GetEnvironmentVariable("SystemDrive") ?? "C:";
        var root = drive.TrimEnd('\\') + "\\";
        return GetVolumeInformation(root, null, 0, out var serial, out _, out _, null, 0)
            ? $"{serial >> 16:X4}-{serial & 0xffff:X4}"
            : null;
    }

    [System.Runtime.Versioning.SupportedOSPlatform("windows")]
    private static Dictionary<string, string> WindowsSchemaV2Factors(bool includeTpm, Action<string, string>? diagnostic)
    {
        // One PowerShell process obtains the CIM-backed SMBIOS/peripheral
        // signals. UTF-8 output keeps non-ASCII hardware strings identical to
        // the native C++ collector. WMIC is never invoked.
        var script =
            "[Console]::OutputEncoding=[Text.UTF8Encoding]::new($false);$OutputEncoding=[Console]::OutputEncoding;$ErrorActionPreference='SilentlyContinue';" +
            "function Emit($n,$v){$c=@($v|?{$_ -ne $null -and ([string]$_).Trim().Length -gt 0}|%{([string]$_).Trim()}|sort);if($c.Count -gt 0){Write-Output ($n+'='+($c -join '|'))}};" +
            "$p=Get-CimInstance Win32_ComputerSystemProduct;Emit 'system_uuid' $p.UUID;Emit 'system_serial' $p.IdentifyingNumber;" +
            "Emit 'chassis_serial' (Get-CimInstance Win32_SystemEnclosure).SerialNumber;" +
            "Emit 'disk_serial' (Get-CimInstance Win32_DiskDrive).SerialNumber;" +
            // Schema v3 fixed disks; the bus values match IsFixedBus.
            "Emit 'fixed_disk_serial' (Get-CimInstance -Namespace root/Microsoft/Windows/Storage MSFT_PhysicalDisk|?{$_.BusType -notin 7,12,13,15}).SerialNumber;" +
            "Emit 'memory_modules' (Get-CimInstance Win32_PhysicalMemory).SerialNumber;" +
            // Win32_NetworkAdapter.PermanentAddress is normally empty. It stays
            // first so any value it did provide keeps its enrolled form;
            // MSFT_NetAdapter supplies it otherwise. The script text must stay
            // identical to the C++ collector.
            "$n=@((Get-CimInstance Win32_NetworkAdapter|?{$_.PhysicalAdapter}).PermanentAddress|?{$_});" +
            "if($n.Count -eq 0){$n=(Get-CimInstance -Namespace root/StandardCimv2 MSFT_NetAdapter|?{$_.ConnectorPresent -and -not $_.Virtual}).PermanentAddress};" +
            "Emit 'nic_identity' $n;" +
            "Emit 'battery_serial' (Get-CimInstance -Namespace root/wmi -ClassName BatteryStaticData).SerialNumber;";
        // Both paths use the same fingerprint. A store created through the
        // PowerShell fallback automatically recovers natively when available.
        if (includeTpm)
            script += "try{$ek=Get-TpmEndorsementKeyInfo -HashAlgorithm Sha256 -ErrorAction Stop;" +
                "if($ek.IsPresent){Emit 'tpm_ek' $ek.PublicKeyHash;'tpm_status=PowerShell fallback: endorsement key available.'}" +
                "elseif($ek -is [string]){'tpm_status=PowerShell fallback: '+$ek}" +
                "else{'tpm_status=PowerShell fallback: endorsement key unavailable.'}}catch{'tpm_status=PowerShell fallback: '+$_.Exception.Message}";
        var factors = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (var line in Run("powershell.exe", 6, "-NoProfile", "-NonInteractive", "-Command", script)
                     .Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            var separator = line.IndexOf('=');
            if (separator > 0 && separator + 1 < line.Length)
            {
                if (line[..separator] == "tpm_status")
                {
                    diagnostic?.Invoke("tpm_ek", line[(separator + 1)..]);
                    continue;
                }
                factors[line[..separator]] = line[(separator + 1)..];
            }
        }
        return factors;
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

        var expert = Run("ioreg", "-rd1", "-c", "IOPlatformExpertDevice");
        Put(factors, "machine_guid", FirstMatch(expert, "\"IOPlatformUUID\"\\s*=\\s*\"([^\"]+)\""));
        Put(factors, "board_serial", FirstMatch(expert, "\"IOPlatformSerialNumber\"\\s*=\\s*\"([^\"]+)\""));
        Put(factors, "system_serial", FirstMatch(expert, "\"IOPlatformSerialNumber\"\\s*=\\s*\"([^\"]+)\""));

        var brand = Run("sysctl", "-n", "machdep.cpu.brand_string").Trim();
        if (brand.Length == 0)
        {
            brand = Run("sysctl", "-n", "hw.model").Trim();
        }
        var cores = Run("sysctl", "-n", "hw.physicalcpu").Trim();
        if (brand.Length > 0 && cores.Length > 0)
        {
            factors["cpu_id"] = $"{brand}-{cores}";
        }

        Put(factors, "mac", FirstMatch(Run("ifconfig", "en0"), "ether\\s+([0-9a-fA-F:]{17})"));
        Put(factors, "nic_identity", MultiInstance(AllMatches(
            Run("networksetup", "-listallhardwareports"), "Ethernet Address:\\s*([0-9a-fA-F:]{17})")));
        Put(factors, "ram_total", Run("sysctl", "-n", "hw.memsize").Trim());
        Put(factors, "volume_id", FirstMatch(Run("diskutil", "info", "-plist", "/"), "<key>VolumeUUID</key>\\s*<string>([^<]+)</string>"));
        Put(factors, "computer_name", NullIfEmpty(Run("scutil", "--get", "ComputerName").Trim()) ?? NullIfEmpty(Run("scutil", "--get", "LocalHostName").Trim()));
        Put(factors, "firmware", FirstMatch(Run("system_profiler", 5, "SPHardwareDataType", "-json"), "\"spmachine_bootrom_version\"\\s*:\\s*\"([^\"]+)\""));
        Put(factors, "memory_modules", MultiInstance(AllMatches(
            Run("system_profiler", 5, "SPMemoryDataType", "-json"), "\"[^\"]*serial[^\"]*\"\\s*:\\s*\"([^\"]+)\"")));
        var battery = Run("ioreg", "-r", "-c", "AppleSmartBattery");
        Put(factors, "battery_serial",
            NullIfEmpty(FirstMatch(battery, "\"BatterySerialNumber\"\\s*=\\s*\"([^\"]+)\""))
            ?? NullIfEmpty(FirstMatch(battery, "\"Serial\"\\s*=\\s*\"?([^\"\\n]+)\"?")));

        var displays = Run("system_profiler", 5, "SPDisplaysDataType", "-json");
        var models = AllMatches(displays, "\"spdisplays_model\"\\s*:\\s*\"([^\"]+)\"");
        if (models.Count > 0)
        {
            factors["gpu_id"] = MultiInstance(models);
        }

        var storage = Run("system_profiler", 5, "SPStorageDataType", "-json");
        var serials = AllMatches(storage, "\"[a-z_]*serial[a-z_]*\"\\s*:\\s*\"([^\"]+)\"");
        if (serials.Count > 0)
        {
            factors["disk_serial"] = MultiInstance(serials);
        }

        // Schema v3 fixed disks: only internal NVMe/SATA buses are listed here;
        // USB storage appears under SPUSBDataType instead.
        Put(factors, "fixed_disk_serial", MultiInstance(AllMatches(
            Run("system_profiler", 5, "SPNVMeDataType", "SPSerialATADataType", "-json"),
            "\"device_serial\"\\s*:\\s*\"([^\"]+)\"")));

        var displayIo = Run("ioreg", "-r", "-c", "IODisplayConnect");
        var blobs = AllMatches(displayIo, "\"IODisplayEDID\"\\s*=\\s*<?([0-9a-fA-F]+)>?");
        if (blobs.Count > 0)
        {
            factors["monitor_edid"] = MultiInstance(blobs.Select(b => b.ToLowerInvariant()));
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
        Put(factors, "system_uuid", ReadTextFile("/sys/class/dmi/id/product_uuid"));
        Put(factors, "system_serial", ReadTextFile("/sys/class/dmi/id/product_serial"));
        Put(factors, "chassis_serial", ReadTextFile("/sys/class/dmi/id/chassis_serial"));
        Put(factors, "memory_modules", MultiInstance(AllMatches(
            Run("dmidecode", "--type", "memory"), "(?m)^\\s*Serial Number:\\s*(\\S.*)$")));
        var nicIds = new List<string>();
        try
        {
            foreach (var iface in Directory.GetDirectories("/sys/class/net").Order())
            {
                if (!Directory.Exists(Path.Join(iface, "device")))
                {
                    continue;
                }
                var value = ReadTextFile(Path.Join(iface, "perm_address"));
                if (!string.IsNullOrEmpty(value) && value != "00:00:00:00:00:00")
                {
                    nicIds.Add(value);
                }
            }
        }
        catch { }
        Put(factors, "nic_identity", MultiInstance(nicIds));
        var batteries = new List<string>();
        try
        {
            foreach (var dir in Directory.GetDirectories("/sys/class/power_supply", "BAT*").Order())
            {
                var value = ReadTextFile(Path.Join(dir, "serial_number"));
                if (!string.IsNullOrEmpty(value)) batteries.Add(value);
            }
        }
        catch { }
        Put(factors, "battery_serial", MultiInstance(batteries));
        foreach (var path in new[] { "/sys/class/tpm/tpm0/device/ek_pub", "/sys/class/tpm/tpm0/ek_pub" })
        {
            try
            {
                var data = File.ReadAllBytes(path);
                if (data.Length > 0)
                {
                    factors["tpm_ek"] = Convert.ToHexString(SHA256.HashData(data)).ToLowerInvariant();
                    break;
                }
            }
            catch { }
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
        Put(factors, "fixed_disk_serial", MultiInstance(LinuxFixedDiskSerials()));

        // Environment.MachineName drops everything after the first '.' on Unix.
        // The other implementations use the full gethostname() value, which
        // Dns.GetHostName returns unchanged.
        try
        {
            Put(factors, "computer_name", System.Net.Dns.GetHostName());
        }
        catch
        {
            // absent
        }
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
        Put(factors, "volume_id", NullIfEmpty(Run("findmnt", "-no", "UUID", "/").Trim()));
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
            factors["monitor_edid"] = MultiInstance(blobs);
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
            factors["gpu_id"] = MultiInstance(gpus);
        }

        return factors;
    }

    // Schema v3 fixed disks on Linux: every block device with a serial that
    // is neither marked removable nor attached through USB. NVMe/SCSI expose
    // device/serial; virtio exposes serial on the block device itself.
    private static IEnumerable<string> LinuxFixedDiskSerials()
    {
        var serials = new List<string>();
        try
        {
            foreach (var block in Directory.GetDirectories("/sys/block").Order(StringComparer.Ordinal))
            {
                if (ReadTextFile(Path.Join(block, "removable")) == "1")
                {
                    continue;
                }
                var target = new DirectoryInfo(block).ResolveLinkTarget(returnFinalTarget: true)?.FullName ?? block;
                if (target.Contains("/usb", StringComparison.Ordinal))
                {
                    continue;
                }
                var serial = ReadTextFile(Path.Join(block, "device", "serial")) ?? ReadTextFile(Path.Join(block, "serial"));
                if (serial is not null)
                {
                    serials.Add(serial);
                }
            }
        }
        catch
        {
            // absent
        }
        return serials;
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

    // Only OS-owned absolute paths are eligible. Process.Start otherwise checks
    // the host executable directory and current directory before PATH on .NET 8.
    internal static string? ResolveTrustedExecutable(string fileName)
    {
        string[] candidates;
        if (OperatingSystem.IsWindows())
        {
            if (!fileName.Equals("powershell.exe", StringComparison.OrdinalIgnoreCase))
            {
                return null;
            }
            candidates = new[]
            {
                Path.Combine(Environment.SystemDirectory, "WindowsPowerShell", "v1.0", "powershell.exe"),
            };
        }
        else if (OperatingSystem.IsMacOS())
        {
            candidates = fileName switch
            {
                "ioreg" => new[] { "/usr/sbin/ioreg" },
                "sysctl" => new[] { "/usr/sbin/sysctl" },
                "ifconfig" => new[] { "/sbin/ifconfig" },
                "networksetup" => new[] { "/usr/sbin/networksetup" },
                "diskutil" => new[] { "/usr/sbin/diskutil" },
                "scutil" => new[] { "/usr/sbin/scutil" },
                "system_profiler" => new[] { "/usr/sbin/system_profiler" },
                "sw_vers" => new[] { "/usr/bin/sw_vers" },
                _ => Array.Empty<string>(),
            };
        }
        else if (OperatingSystem.IsLinux())
        {
            candidates = fileName switch
            {
                "dmidecode" => new[] { "/usr/sbin/dmidecode", "/sbin/dmidecode" },
                "findmnt" => new[] { "/usr/bin/findmnt", "/bin/findmnt" },
                _ => Array.Empty<string>(),
            };
        }
        else
        {
            return null;
        }

        return candidates.FirstOrDefault(File.Exists);
    }

    private static void ConfigureTrustedEnvironment(ProcessStartInfo info, string executable)
    {
        info.Environment.Clear();
        if (OperatingSystem.IsWindows())
        {
            var systemDirectory = Environment.SystemDirectory;
            var windowsDirectory = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
            if (string.IsNullOrEmpty(windowsDirectory))
            {
                windowsDirectory = Directory.GetParent(systemDirectory)?.FullName ?? "C:\\Windows";
            }
            var powerShellHome = Path.GetDirectoryName(executable)!;
            info.Environment["ComSpec"] = Path.Combine(systemDirectory, "cmd.exe");
            info.Environment["PATH"] = string.Join(';', systemDirectory, windowsDirectory, powerShellHome);
            info.Environment["PATHEXT"] = ".COM;.EXE;.BAT;.CMD";
            info.Environment["PSModulePath"] = Path.Combine(powerShellHome, "Modules");
            info.Environment["SystemDrive"] = Path.GetPathRoot(windowsDirectory)?.TrimEnd('\\') ?? "C:";
            info.Environment["SystemRoot"] = windowsDirectory;
            info.Environment["WINDIR"] = windowsDirectory;
        }
        else
        {
            info.Environment["PATH"] = "/usr/bin:/bin:/usr/sbin:/sbin";
            info.Environment["LANG"] = "C";
            info.Environment["LC_ALL"] = "C";
        }
    }

    private static string Run(string fileName, params string[] arguments) =>
        Run(fileName, 4, arguments);

    private static string Run(string fileName, int timeoutSeconds, params string[] arguments)
    {
        try
        {
            var executable = ResolveTrustedExecutable(fileName);
            if (executable is null)
            {
                return "";
            }
            var info = new ProcessStartInfo
            {
                FileName = executable,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                CreateNoWindow = true,
                StandardOutputEncoding = Encoding.UTF8,
                StandardErrorEncoding = Encoding.UTF8,
            };
            foreach (var argument in arguments)
            {
                info.ArgumentList.Add(argument);
            }
            ConfigureTrustedEnvironment(info, executable);
            using var process = Process.Start(info);
            if (process is null)
            {
                return "";
            }
            var output = process.StandardOutput.ReadToEndAsync();
            var errors = process.StandardError.ReadToEndAsync(); // drained so the child never blocks on a full pipe
            var timeout = TimeSpan.FromSeconds(timeoutSeconds);
            var elapsed = Stopwatch.StartNew();
            if (!process.WaitForExit(timeout))
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
            // A helper process that inherited the pipes can hold them open
            // after the direct child exits, so end-of-stream may never arrive.
            // Bound that wait too, with a short grace period for buffered output.
            var remaining = timeout - elapsed.Elapsed;
            var grace = TimeSpan.FromMilliseconds(500);
            if (!Task.WaitAll(new Task[] { output, errors }, remaining > grace ? remaining : grace))
            {
                return "";
            }
            return output.Result;
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
