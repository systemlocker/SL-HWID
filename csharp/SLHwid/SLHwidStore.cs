using System.Diagnostics;
using System.Security.Cryptography;

namespace SLHwid;

// Persists the module's own random value and the shared device helper blob.
// Windows pins both values to one registry hive (HKLM with an HKCU fallback);
// other platforms use files in the platform's data directory. All formats
// are the normative cross-language ones.
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

internal enum RegistryRootSelection
{
    None,
    Machine,
    User,
}

internal static class RegistryRootPolicy
{
    internal static RegistryRootSelection Select(
        bool machineHelper, bool machineSlstore, bool userHelper, bool userSlstore) =>
        Select(machineHelper, machineSlstore, userHelper, userSlstore, userMirrorsMachine: false);

    // userMirrorsMachine: both hives hold the same store secret, so the user
    // hive is a per-user copy of the machine generation (same key and HWID)
    // that a non-elevated process wrote because it cannot update HKLM. That
    // copy is the one this user can keep refreshed, so it wins.
    internal static RegistryRootSelection Select(
        bool machineHelper, bool machineSlstore, bool userHelper, bool userSlstore, bool userMirrorsMachine)
    {
        if (machineHelper && machineSlstore && userHelper && userSlstore && userMirrorsMachine)
            return RegistryRootSelection.User;
        if (machineHelper && machineSlstore) return RegistryRootSelection.Machine;
        if (userHelper && userSlstore) return RegistryRootSelection.User;
        if (machineHelper) return RegistryRootSelection.Machine;
        if (userHelper) return RegistryRootSelection.User;
        if (machineSlstore) return RegistryRootSelection.Machine;
        if (userSlstore) return RegistryRootSelection.User;
        return RegistryRootSelection.None;
    }
}

internal static class SLHwidStore
{
    private const string LockFileName = ".slhwid.lock";
    private const string LockHeader = "SLHwidLockV1";
    private static readonly TimeSpan LockWait = TimeSpan.FromSeconds(30);
    // Holders keep the marker for milliseconds (factor collection happens
    // outside the lock), so any older marker has been abandoned.
    private static readonly TimeSpan StaleLockAge = TimeSpan.FromMinutes(2);

    public static ISSStore CreateDefault(string overridePath) =>
        overridePath.Length > 0 ? new DirStore(overridePath) : CreatePlatformDefault();

    private static ISSStore CreatePlatformDefault()
    {
        if (OperatingSystem.IsWindows())
        {
            return new RegistryStore();
        }
        var home = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        // An empty XDG_DATA_HOME means "unset" (as in the C++ implementation).
        // Path.Combine("", ...) would otherwise yield a store relative to the
        // working directory, which re-enrolls whenever the app starts elsewhere.
        var xdg = Environment.GetEnvironmentVariable("XDG_DATA_HOME");
        var directory = OperatingSystem.IsMacOS()
            ? Path.Combine(home, "Library", "Application Support", "SystemLocker")
            : Path.Combine(string.IsNullOrEmpty(xdg) ? Path.Combine(home, ".local", "share") : xdg, "systemlocker");
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
        var deniedAttempts = 0;
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
            catch (Exception error) when (error is IOException or UnauthorizedAccessException)
            {
                // Windows reports a marker that another process is deleting
                // as "access denied" instead of "exists". That state lasts
                // milliseconds; a persistent denial is a real permission error.
                if (error is UnauthorizedAccessException && ++deniedAttempts > 20)
                {
                    throw;
                }
                var existing = ReadLock(lockPath);
                if (existing is not null && IsStale(lockPath, existing.Value.ProcessId))
                {
                    RemoveIfUnchanged(lockPath, existing.Value.Contents);
                    continue;
                }
                if (DateTime.UtcNow >= deadline)
                {
                    throw new IOException("slhwid: storage is busy; retry the operation", error);
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
        catch (Exception error) when (error is IOException or UnauthorizedAccessException)
        {
            return null;
        }
    }

    private static bool IsStale(string path, int? processId)
    {
        if (processId is not null && !ProcessMayBeAlive(processId.Value))
        {
            return true;
        }
        // A live-looking PID can belong to an unrelated process after PID
        // reuse, or to a holder that failed to delete its marker. Without this
        // age limit such a marker would block the store until that process exits.
        try
        {
            return DateTime.UtcNow - File.GetLastWriteTimeUtc(path) >= StaleLockAge;
        }
        catch (Exception error) when (error is IOException or UnauthorizedAccessException)
        {
            return false;
        }
    }

    private static bool ProcessMayBeAlive(int processId)
    {
        try
        {
            using var process = Process.GetProcessById(processId);
            return !process.HasExited;
        }
        catch (ArgumentException)
        {
            return false; // no such process
        }
        catch (Exception error) when (error is InvalidOperationException
                                          or System.ComponentModel.Win32Exception
                                          or NotSupportedException)
        {
            // Access to another user's process can be denied. A failed check
            // is not evidence of termination; the age limit still applies.
            return true;
        }
    }

    private static void RemoveIfUnchanged(string path, string expected)
    {
        // On Windows, deleting fails while another process is reading the
        // marker. Giving up would leave a marker that names a live process,
        // so retry briefly; the contents check stops if it was replaced.
        for (var attempt = 0; attempt < 20; attempt++)
        {
            try
            {
                if (File.ReadAllText(path) == expected)
                {
                    File.Delete(path);
                }
                return;
            }
            catch (Exception error) when (error is FileNotFoundException or DirectoryNotFoundException)
            {
                return; // Another process released or recovered the marker.
            }
            catch (Exception error) when (error is IOException or UnauthorizedAccessException)
            {
                Thread.Sleep(10);
            }
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
    private Microsoft.Win32.RegistryHive? _selectedHive;

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
        var root = _selectedHive ?? SelectHive();
        var data = root is null ? null : Read(root.Value, "SLStore");
        return data is null ? null : SLHwidStore.UnwrapSlstore(data);
    }

    public void WriteSlstore(byte[] value)
    {
        var blob = SLHwidCore.SlstorePrefix.Concat(value).ToArray();
        WriteSelected("SLStore", blob);
    }

    public byte[]? ReadHelper()
    {
        var root = _selectedHive ?? SelectHive();
        return root is null ? null : Read(root.Value, "HWID-device");
    }

    public void WriteHelper(byte[] blob)
    {
        WriteSelected("HWID-device", blob);
    }

    // Only a well-formed secret completes a generation. A malformed HKLM
    // secret that a non-elevated ForceReenroll could not overwrite must not
    // outrank the replacement generation it wrote to HKCU.
    internal static bool IsWellFormedSlstore(byte[]? data) =>
        data is not null && data.Length == SLHwidCore.SlstorePrefix.Length + 32
        && data.AsSpan(0, SLHwidCore.SlstorePrefix.Length).SequenceEqual(SLHwidCore.SlstorePrefix);

    private Microsoft.Win32.RegistryHive? SelectHive()
    {
        // A helper and its mandatory store secret form one generation. Never
        // choose the two values independently across HKLM/HKCU: that can make
        // valid data look corrupt after an elevation or reinstall change.
        var machineSlstore = Read(Microsoft.Win32.RegistryHive.LocalMachine, "SLStore");
        var userSlstore = Read(Microsoft.Win32.RegistryHive.CurrentUser, "SLStore");
        var selected = RegistryRootPolicy.Select(
            Read(Microsoft.Win32.RegistryHive.LocalMachine, "HWID-device") is not null,
            IsWellFormedSlstore(machineSlstore),
            Read(Microsoft.Win32.RegistryHive.CurrentUser, "HWID-device") is not null,
            IsWellFormedSlstore(userSlstore),
            IsWellFormedSlstore(machineSlstore) && machineSlstore!.AsSpan().SequenceEqual(userSlstore));
        _selectedHive = selected switch
        {
            RegistryRootSelection.Machine => Microsoft.Win32.RegistryHive.LocalMachine,
            RegistryRootSelection.User => Microsoft.Win32.RegistryHive.CurrentUser,
            _ => null,
        };
        return _selectedHive;
    }

    private void WriteSelected(string name, byte[] data)
    {
        if (_selectedHive is { } selected)
        {
            if (Write(selected, name, data))
            {
                return;
            }
            // A non-elevated process cannot update an HKLM generation that an
            // elevated one created. Continue in HKCU instead of never absorbing
            // drift again: copying the machine secret first makes the user
            // hive a complete mirror with the same key, so the HWID is kept.
            if (selected == Microsoft.Win32.RegistryHive.LocalMachine
                && (name == "SLStore"
                    || Read(Microsoft.Win32.RegistryHive.LocalMachine, "SLStore") is { } secret
                    && Write(Microsoft.Win32.RegistryHive.CurrentUser, "SLStore", secret))
                && Write(Microsoft.Win32.RegistryHive.CurrentUser, name, data))
            {
                _selectedHive = Microsoft.Win32.RegistryHive.CurrentUser;
                return;
            }
            throw new IOException("slhwid: registry write failed");
        }
        foreach (var root in Roots())
        {
            if (Write(root, name, data))
            {
                _selectedHive = root;
                return;
            }
        }
        throw new IOException("slhwid: registry write failed");
    }

    public IDisposable AcquireLock() => SLHwidStore.AcquireFileLock(SLHwidStore.LocalLockDirectory());

    private static IEnumerable<Microsoft.Win32.RegistryHive> Roots()
    {
        yield return Microsoft.Win32.RegistryHive.LocalMachine;
        yield return Microsoft.Win32.RegistryHive.CurrentUser;
    }
}
