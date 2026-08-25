using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;

namespace SLHwid;

/// <summary>Configuration for one <see cref="SLHwid.Prepare"/> call.</summary>
public sealed class SLHwidOptions
{
    /// <summary>Optionally redirects storage to a directory (files on every
    /// platform). Empty uses the platform default.</summary>
    public string StorePath { get; init; } = "";

    /// <summary>Names additional hard-locked slots beyond the default "slstore".</summary>
    public IReadOnlyList<string> ExtraMandatory { get; init; } = Array.Empty<string>();

    /// <summary>Discards the shared device helper data and enrolls a fresh
    /// key (new HWID). This affects all applications sharing the store; the
    /// application must then run its server-side device reset.</summary>
    public bool ForceReenroll { get; init; }
}

/// <summary>The stored secret could not be recovered from current hardware.</summary>
public sealed class SLHwidDriftException : Exception
{
    /// <summary>Number of factors currently present.</summary>
    public int Present { get; }

    /// <summary>Threshold needed for recovery.</summary>
    public int Needed { get; }

    /// <summary>Hard-locked slots that changed or are absent.</summary>
    public IReadOnlyList<string> MissingMandatory { get; }

    /// <summary>Whether a hard-locked slot is the cause (vs. plain drift).</summary>
    public bool Mandatory { get; }

    public SLHwidDriftException(int present, int needed, IReadOnlyList<string> missing, bool mandatory)
        : base(mandatory
            ? $"slhwid: mandatory factor(s) {string.Join(", ", missing)} changed or absent; re-activation required"
            : $"slhwid: hardware drifted past the recovery threshold ({present} factors present, {needed} needed); re-activation required")
    {
        Present = present;
        Needed = needed;
        MissingMandatory = missing;
        Mandatory = mandatory;
    }
}

/// <summary>Stored helper data failed its integrity check (distinct from drift).</summary>
public sealed class SLHwidCorruptDataException : Exception
{
    public SLHwidCorruptDataException(string message) : base(message) { }
}

/// <summary>One prepared secret-sharing HWID. <see cref="Hwid"/> is available
/// immediately; <see cref="Commit"/> persists a re-centered share set and must
/// only be called after the server accepted the authentication that used it.</summary>
public sealed class SLHwidSession
{
    /// <summary>The transmitted device identifier (43 characters, base64url).</summary>
    public string Hwid { get; }

    /// <summary>Whether this session created a key the server has never seen.</summary>
    public bool FreshlyEnrolled { get; }

    /// <summary>Enrolled slots that were dead at prepare time.</summary>
    public IReadOnlyList<string> DriftedSlots { get; private set; }

    /// <summary>Whether any slot was dead (commit will re-center).</summary>
    public bool PendingRefresh { get; private set; }

    internal ulong[]? Key { get; private set; }
    internal Draw? Draw { get; }
    internal Dictionary<string, string> Factors { get; }
    internal HashSet<string> Mandatory { get; }
    internal ISSStore Store { get; }
    internal byte[] ExpectedHelper { get; }
    private bool _committed;

    internal SLHwidSession(string hwid, bool fresh, IReadOnlyList<string> drifted, bool pending,
        ulong[]? key, Draw draw, Dictionary<string, string> factors, HashSet<string> mandatory,
        ISSStore store, byte[] expectedHelper)
    {
        Hwid = hwid;
        FreshlyEnrolled = fresh;
        DriftedSlots = drifted;
        PendingRefresh = pending;
        Key = key;
        Draw = draw;
        Factors = factors;
        Mandatory = mandatory;
        Store = store;
        ExpectedHelper = expectedHelper.ToArray();
    }

    /// <summary>Re-shares the recovered key over the hardware observed at
    /// prepare time and persists the new helper data. Failures are non-fatal:
    /// the next launch re-derives everything.</summary>
    public void Commit()
    {
        if (_committed || Key is null)
        {
            Key = null;
            return;
        }
        _committed = true;
        try
        {
            using var storageLock = SLHwidStore.AcquireLock(Store);
            var current = Store.ReadHelper();
            if (current is null || !CryptographicOperations.FixedTimeEquals(current, ExpectedHelper))
            {
                // Another module user refreshed or re-enrolled the shared
                // device after this session prepared. Never overwrite its
                // newer state with a stale snapshot.
                return;
            }
            var (blob, written) = SLHwidCore.RefreshCore(Key, Factors, Mandatory, Draw!);
            if (written)
            {
                Store.WriteHelper(blob!);
                PendingRefresh = false;
                DriftedSlots = Array.Empty<string>();
            }
        }
        catch (Exception)
        {
            // the next launch re-derives
        }
        finally
        {
            Array.Clear(Key); // best-effort zeroization
            Key = null;
        }
    }
}

/// <summary>Fault-tolerant secret-sharing HWID module:
/// a random 244-bit key is shared across hardware factors with a threshold
/// scheme, and the transmitted HWID is a domain-separated hash of that key.
/// Ordinary hardware drift leaves the HWID unchanged; mandatory slots (by
/// default the module's own persisted random value) can never be routed
/// around.</summary>
public static class SLHwid
{
    private static readonly Regex SlotNamePattern = new("^[a-z][a-z0-9_]{0,31}$", RegexOptions.Compiled);
    /// <summary>Collects factors and recovers (or enrolls) the secret-sharing
    /// HWID for the current device. Enrollment persists immediately; a recovered
    /// session persists nothing until <see cref="SLHwidSession.Commit"/>.</summary>
    public static SLHwidSession Prepare(SLHwidOptions options) =>
        PrepareWith(options, SLHwidCollectors.Collect, RandomSource, null);

    internal static byte[] RandomSource(int n)
    {
        var bytes = new byte[n];
        RandomNumberGenerator.Fill(bytes);
        return bytes;
    }

    internal static SLHwidSession PrepareWith(SLHwidOptions options,
        Func<Dictionary<string, string>> collect, Func<int, byte[]> source, ISSStore? store)
    {
        var requestedMandatory = new HashSet<string> { "slstore" };
        foreach (var name in options.ExtraMandatory)
        {
            if (!SlotNamePattern.IsMatch(name))
            {
                throw new InvalidOperationException($"slhwid: invalid extra mandatory slot name '{name}'");
            }
            requestedMandatory.Add(name);
        }

        var rawFactors = SLHwidCore.NormalizeFactors(collect());
        store ??= SLHwidStore.CreateDefault(options.StorePath);
        using var storageLock = SLHwidStore.AcquireLock(store);
        var existing = store.ReadHelper();

        // The slstore factor is ours, not collectable hardware: recovery
        // injects the persisted value (read-only). An absent value with an
        // existing helper is intentional tampering and RecoverCore reports
        // it as a hard-locked mandatory failure below.
        if (existing is not null && !options.ForceReenroll && !rawFactors.ContainsKey("slstore"))
        {
            var value = store.ReadSlstore();
            if (value is not null)
            {
                rawFactors["slstore"] = Convert.ToHexString(value).ToLowerInvariant();
            }
        }

        if (existing is null || options.ForceReenroll)
        {
            if (!rawFactors.ContainsKey("slstore"))
            {
                rawFactors["slstore"] = EnsureSlstore(store, source);
            }
            var factors = SLHwidCore.ProjectFactors(rawFactors, SLHwidCore.CurrentNormVersion);
            var mandatory = SLHwidCore.MapMandatoryToCurrent(requestedMandatory);
            foreach (var name in mandatory.Order())
            {
                if (!factors.TryGetValue(name, out var value) || value.Length == 0)
                {
                    throw new InvalidOperationException($"slhwid: mandatory factor '{name}' is not available on this machine");
                }
            }
            var n = factors.Count;
            var m = mandatory.Count;
            var t = SLHwidCore.Threshold(n, m);
            var draw = new Draw(source);
            var k = new[] { draw.Elem(), draw.Elem(), draw.Elem(), draw.Elem() };
            var (shares, salt) = SLHwidCore.BuildShares(k, SLHwidCore.SlotList(factors, mandatory), t, draw);
            var blob = SLHwidCore.SerializeHelper(shares, mandatory, t, salt, SLHwidCore.CheckWord(k));
            store.WriteHelper(blob);
            return new SLHwidSession(SLHwidCore.HwidOf(k), true, Array.Empty<string>(), false,
                k, new Draw(source), factors, mandatory, store, blob);
        }

        SLHwidCore.Helper helper;
        try
        {
            helper = SLHwidCore.ParseHelper(existing);
        }
        catch (SecretSharingCorruptException)
        {
            throw new SLHwidCorruptDataException("slhwid: stored helper data is corrupt; re-enroll to recover");
        }
        var recoveryFactors = SLHwidCore.ProjectFactors(rawFactors, helper.NormVersion);
        var result = SLHwidCore.RecoverCore(existing, recoveryFactors);
        if (!result.Ok)
        {
            if (result.Reason == "corrupt")
            {
                throw new SLHwidCorruptDataException("slhwid: stored helper data is corrupt; re-enroll to recover");
            }
            throw new SLHwidDriftException(result.Present, result.Needed, result.Missing, result.Reason == "mandatory");
        }
        // Do not let another application weaken hard locks selected by the
        // application that enrolled the shared device helper.
        var storedMandatory = SLHwidCore.MapMandatoryToCurrent(
            helper.Slots.Where(slot => slot.Mandatory).Select(slot => slot.Name));
        var currentFactors = SLHwidCore.ProjectFactors(rawFactors, SLHwidCore.CurrentNormVersion);
        return new SLHwidSession(result.Hwid, false, result.Dead, result.Pending,
            result.Key!, new Draw(source), currentFactors, storedMandatory, store, existing);
    }

    private static string EnsureSlstore(ISSStore store, Func<int, byte[]> source)
    {
        var existing = store.ReadSlstore();
        if (existing is not null)
        {
            if (existing.Length != 32)
            {
                throw new SLHwidCorruptDataException("slhwid: store secret has the wrong size");
            }
            return Convert.ToHexString(existing).ToLowerInvariant();
        }
        var value = source(32);
        if (value.Length != 32)
        {
            throw new InvalidOperationException("slhwid: randomness failed");
        }
        store.WriteSlstore(value);
        var encoded = Convert.ToHexString(value).ToLowerInvariant();
        SLHwidCore.Wipe(value);
        return encoded;
    }
}
