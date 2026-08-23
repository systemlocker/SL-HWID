using System.Diagnostics;
using System.Security.Cryptography;

namespace SLHwid;

// Persists the module's own random value and the shared device helper blob.
// Windows uses the registry (HKLM with an HKCU fallback); other
// platforms use files in the platform's data directory. All formats are the
// normative cross-language ones.
internal interface ISSStore
{
    /// <summary>Returns the 32-byte store secret, or null when absent.</summary>
    byte[]? ReadSlstore();

    void WriteSlstore(byte[] value);

    /// <summary>Returns the shared device helper blob, or null when absent.</summary>
    byte[]? ReadHelper();

    void WriteHelper(byte[] blob);
}

internal interface ISSStoreLockable
{
    IDisposable AcquireLock();
}

internal static class SLHwidStore
{
    private const string LockFileName = ".slhwid.lock";
    private const string LockHeader = "SLHwidLockV1";
    private static readonly TimeSpan LockWait = TimeSpan.FromSeconds(30);
    private static readonly TimeSpan UnknownLockGrace = TimeSpan.FromMinutes(2);

    public static ISSStore CreateDefault(string overridePath) =>
        overridePath.Length > 0 ? new DirStore(overridePath) : CreatePlatformDefault();

    private static ISSStore CreatePlatformDefault()
    {
        if (OperatingSystem.IsWindows())
        {
            return new RegistryStore();
        }
        var home = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        var directory = OperatingSystem.IsMacOS()
            ? Path.Combine(home, "Library", "Application Support", "SystemLocker")
            : Path.Combine(Environment.GetEnvironmentVariable("XDG_DATA_HOME") ?? Path.Combine(home, ".local", "share"), "systemlocker");
        return new DirStore(directory);
    }

    internal static byte[] UnwrapSlstore(byte[] data)
    {
        if (data.Length != SLHwidCore.SlstorePrefix.Length + 32)
        {
            throw new SLHwidCorruptDataException("slhwid: store secret has the wrong size");
        }
        if (!SLHwidCore.SlstorePrefix.AsSpan().SequenceEqual(data.AsSpan(0, SLHwidCore.SlstorePrefix.Length)))
        {
            throw new SLHwidCorruptDataException("slhwid: store secret prefix mismatch");
        }
        return data.AsSpan(SLHwidCore.SlstorePrefix.Length).ToArray();
    }

    internal static IDisposable AcquireLock(ISSStore store) =>
        store is ISSStoreLockable lockable ? lockable.AcquireLock() : NoopLock.Instance;

    internal static IDisposable AcquireFileLock(string directory)
    {
        Directory.CreateDirectory(directory);
        if (!OperatingSystem.IsWindows())
        {
            File.SetUnixFileMode(directory, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
        }
        var lockPath = Path.Join(directory, LockFileName);
        var owner = $"{LockHeader}\n{Environment.ProcessId}\n{Convert.ToHexString(RandomNumberGenerator.GetBytes(16)).ToLowerInvariant()}\n";
        var deadline = DateTime.UtcNow + LockWait;
        while (true)
        {
            try
            {
                using var file = new FileStream(lockPath, FileMode.CreateNew, FileAccess.Write, FileShare.None);
                using var writer = new StreamWriter(file, leaveOpen: true);
                writer.Write(owner);
                writer.Flush();
                file.Flush(flushToDisk: true);
                return new FileLock(lockPath, owner);
            }
            catch (IOException)
            {
                var existing = ReadLock(lockPath);
                if (existing is not null && IsStale(lockPath, existing.Value.ProcessId))
                {
                    RemoveIfUnchanged(lockPath, existing.Value.Contents);
                    continue;
                }
                if (DateTime.UtcNow >= deadline)
                {
                    throw new IOException("slhwid: storage is busy; retry the operation");
                }
                Thread.Sleep(50);
            }
        }
    }

    internal static string LocalLockDirectory()
    {
        var local = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        if (string.IsNullOrEmpty(local))
        {
            local = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "AppData", "Local");
        }
        return Path.Combine(local, "SystemLocker");
    }

    private static (string Contents, int? ProcessId)? ReadLock(string path)
    {
        try
        {
            var contents = File.ReadAllText(path);
            var lines = contents.Split('\n');
            if (lines.Length == 4 && lines[0] == LockHeader && int.TryParse(lines[1], out var processId) && processId > 0 && !string.IsNullOrEmpty(lines[2]))
            {
                return (contents, processId);
            }
            return (contents, null);
        }
        catch (IOException)
        {
            return null;
        }
    }

    private static bool IsStale(string path, int? processId)
    {
        if (processId is not null)
        {
            try
            {
                return Process.GetProcessById(processId.Value).HasExited;
            }
            catch (ArgumentException)
            {
                return true;
            }
            catch (InvalidOperationException)
            {
                return false;
            }
        }
        try
        {
            return DateTime.UtcNow - File.GetLastWriteTimeUtc(path) >= UnknownLockGrace;
        }
        catch (IOException)
        {
            return false;
        }
    }

    private static void RemoveIfUnchanged(string path, string expected)
    {
        try
        {
            if (File.ReadAllText(path) == expected)
            {
                File.Delete(path);
            }
        }
        catch (IOException)
        {
            // Another process released or recovered the marker.
        }
    }

    private sealed class FileLock(string path, string owner) : IDisposable
    {
        private string? _owner = owner;

        public void Dispose()
        {
            if (Interlocked.Exchange(ref _owner, null) is { } expected)
            {
                RemoveIfUnchanged(path, expected);
            }
        }
    }

    private sealed class NoopLock : IDisposable
    {
        internal static readonly NoopLock Instance = new();

        public void Dispose() { }
    }
}

internal sealed class DirStore(string directory) : ISSStore, ISSStoreLockable
{
    private readonly string _directory = directory;

    public byte[]? ReadSlstore()
    {
        try
        {
            var data = File.ReadAllBytes(Path.Join(_directory, "slstore.bin"));
            return SLHwidStore.UnwrapSlstore(data);
        }
        catch (FileNotFoundException)
        {
            return null;
        }
        catch (DirectoryNotFoundException)
        {
            return null;
        }
    }

    public void WriteSlstore(byte[] value) =>
        Write("slstore.bin", SLHwidCore.SlstorePrefix.Concat(value).ToArray());

    public byte[]? ReadHelper()
    {
        try
        {
            return File.ReadAllBytes(Path.Join(_directory, "hwid-device.bin"));
        }
        catch (FileNotFoundException)
        {
            return null;
        }
        catch (DirectoryNotFoundException)
        {
            return null;
        }
    }

    public void WriteHelper(byte[] blob) => Write("hwid-device.bin", blob);

    public IDisposable AcquireLock() => SLHwidStore.AcquireFileLock(_directory);

    private void Write(string name, byte[] data)
    {
        Directory.CreateDirectory(_directory);
        if (!OperatingSystem.IsWindows())
        {
            File.SetUnixFileMode(_directory, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
        }
        var target = Path.Join(_directory, name);
        var temporary = Path.Join(_directory, $".{name}.{Environment.ProcessId}.{Convert.ToHexString(RandomNumberGenerator.GetBytes(8)).ToLowerInvariant()}.tmp");
        try
        {
            using (var file = new FileStream(temporary, FileMode.CreateNew, FileAccess.Write, FileShare.None))
            {
                file.Write(data);
                file.Flush(flushToDisk: true);
            }
            if (!OperatingSystem.IsWindows())
            {
                File.SetUnixFileMode(temporary, UnixFileMode.UserRead | UnixFileMode.UserWrite);
            }
            File.Move(temporary, target, overwrite: true);
        }
        finally
        {
            if (File.Exists(temporary))
            {
                File.Delete(temporary);
            }
        }
        if (!OperatingSystem.IsWindows())
        {
            File.SetUnixFileMode(target, UnixFileMode.UserRead | UnixFileMode.UserWrite);
        }
    }
}

[System.Runtime.Versioning.SupportedOSPlatform("windows")]
internal sealed class RegistryStore : ISSStore, ISSStoreLockable
{
    private const string SubKey = @"SOFTWARE\SystemLocker";

    private static byte[]? Read(Microsoft.Win32.RegistryHive hive, string name)
    {
        try
        {
            using var root = Microsoft.Win32.RegistryKey.OpenBaseKey(
                hive, Microsoft.Win32.RegistryView.Registry64);
            using var key = root.OpenSubKey(SubKey, writable: false);
            return key?.GetValue(name) as byte[];
        }
        catch
        {
            return null;
        }
    }

    private static bool Write(Microsoft.Win32.RegistryHive hive, string name, byte[] data)
    {
        try
        {
            using var root = Microsoft.Win32.RegistryKey.OpenBaseKey(
                hive, Microsoft.Win32.RegistryView.Registry64);
            using var key = root.CreateSubKey(SubKey, writable: true);
            key.SetValue(name, data, Microsoft.Win32.RegistryValueKind.Binary);
            return true;
        }
        catch
        {
            return false;
        }
    }

    public byte[]? ReadSlstore()
    {
        foreach (var root in Roots())
        {
            var data = Read(root, "SLStore");
            if (data is not null)
            {
                return SLHwidStore.UnwrapSlstore(data);
            }
        }
        return null;
    }

    public void WriteSlstore(byte[] value)
    {
        var blob = SLHwidCore.SlstorePrefix.Concat(value).ToArray();
        if (!Write(Microsoft.Win32.RegistryHive.LocalMachine, "SLStore", blob) &&
            !Write(Microsoft.Win32.RegistryHive.CurrentUser, "SLStore", blob))
        {
            throw new IOException("slhwid: registry write failed");
        }
    }

    public byte[]? ReadHelper()
    {
        foreach (var root in Roots())
        {
            if (Read(root, "HWID-device") is { } blob)
            {
                return blob;
            }
        }
        return null;
    }

    public void WriteHelper(byte[] blob)
    {
        if (!Write(Microsoft.Win32.RegistryHive.LocalMachine, "HWID-device", blob) &&
            !Write(Microsoft.Win32.RegistryHive.CurrentUser, "HWID-device", blob))
        {
            throw new IOException("slhwid: registry write failed");
        }
    }

    public IDisposable AcquireLock() => SLHwidStore.AcquireFileLock(SLHwidStore.LocalLockDirectory());

    private static IEnumerable<Microsoft.Win32.RegistryHive> Roots()
    {
        yield return Microsoft.Win32.RegistryHive.LocalMachine;
        yield return Microsoft.Win32.RegistryHive.CurrentUser;
    }
}
