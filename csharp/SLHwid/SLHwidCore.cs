using System.Security.Cryptography;
using System.Text;

namespace SLHwid;

// Pure cryptographic core of the §4A secret-sharing HWID module:
// GF(2^61-1) arithmetic on ulong, four-limb secret sharing, x-derivation,
// helper-blob serialization, recovery and refresh. Platform-free; the
// lifecycle in SLHwid wires it to collectors, storage and the
// CSPRNG.
internal static class SLHwidCore
{
    public const ulong Prime = (1UL << 61) - 1;
    public const string HelperMagic = "SLSSHWID";
    public static readonly byte[] SlstorePrefix = "SLSTOR1"u8.ToArray();

    public static ulong Addmod(ulong a, ulong b)
    {
        var s = a + b; // a, b < p < 2^61 → s < 2^62, no overflow
        return s >= Prime ? s - Prime : s;
    }

    public static ulong Submod(ulong a, ulong b) => a >= b ? a - b : a + Prime - b;

    // Reduces any x < 2^64 into [0, p): 2^61 ≡ 1 (mod p).
    private static ulong Red64(ulong x)
    {
        var r = (x & Prime) + (x >> 61); // < 2^61 + 8
        return r >= Prime ? r - Prime : r;
    }

    // Multiplies two field elements using 31/30-bit half splits so every
    // intermediate product fits in ulong (portable MSVC-safe form).
    public static ulong Mulmod(ulong a, ulong b)
    {
        const ulong lo31 = 0x7FFFFFFFUL;
        var alo = a & lo31;
        var ahi = a >> 31; // alo < 2^31, ahi < 2^30
        var blo = b & lo31;
        var bhi = b >> 31;
        var ll = alo * blo;          // < 2^62
        var t = alo * bhi + ahi * blo; // < 2^62
        var hh = ahi * bhi;          // < 2^60
        // full product = ll + t·2^31 + hh·2^62, and 2^62 ≡ 2 (mod p)
        var th = t >> 31;
        var tl = t & lo31;
        var r = Red64(ll);
        r = Addmod(r, Red64(tl << 31));
        r = Addmod(r, Red64(th << 1));
        r = Addmod(r, Red64(hh << 1));
        return r;
    }

    // a^(−1) mod p via iterative extended Euclid (p prime and a ≠ 0).
    public static ulong Invmod(ulong a)
    {
        long lm = 1, hm = 0;
        long low = (long)a, high = (long)Prime;
        while (low > 1)
        {
            var r = high / low;
            (lm, hm) = (hm - lm * r, lm);
            (low, high) = (high - low * r, low);
        }
        if (lm < 0)
        {
            lm += (long)Prime;
        }
        return (ulong)lm;
    }

    public static void Wipe(byte[] bytes) => Array.Clear(bytes);

    // ── derivation ─────────────────────────────────────────────────

    public static ulong DeriveX(string slot, string value, byte salt)
    {
        var input = new byte[12 + slot.Length + value.Length]; // label + \0 + salt + \0 + slot + \0 + value
        var offset = 0;
        void Put(byte[] bytes)
        {
            bytes.CopyTo(input, offset);
            offset += bytes.Length;
        }
        Put("SL-SS-X1"u8.ToArray());
        input[offset++] = 0;
        input[offset++] = salt;
        input[offset++] = 0;
        Put(Encoding.ASCII.GetBytes(slot));
        input[offset++] = 0;
        Put(Encoding.UTF8.GetBytes(value));
        var h = SHA256.HashData(input);
        var v = BitConverter.ToUInt64(h, 0) & Prime;
        return 1 + v % (Prime - 1);
    }

    public static byte[] KeyBytes(ulong[] k)
    {
        var outBytes = new byte[32];
        for (var i = 0; i < 4; i++)
        {
            BitConverter.TryWriteBytes(outBytes.AsSpan(i * 8), k[i]);
        }
        return outBytes;
    }

    public static byte[] CheckWord(ulong[] k) =>
        SHA256.HashData(PrependDomain((byte)0x01, "SL-SS-CW1", k));

    public static string HwidOf(ulong[] k)
    {
        var digest = SHA256.HashData(PrependDomain((byte)0x02, "SL-SS-ID1", k));
        return Base64Url(digest);
    }

    private static byte[] PrependDomain(byte prefix, string label, ulong[] k)
    {
        var input = new byte[1 + label.Length + 32];
        input[0] = prefix;
        Encoding.ASCII.GetBytes(label, input.AsSpan(1));
        KeyBytes(k).CopyTo(input, 1 + label.Length);
        return input;
    }

    public static string Base64Url(byte[] data) =>
        Convert.ToBase64String(data).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    public static bool CtEqual(byte[] a, byte[] b) =>
        CryptographicOperations.FixedTimeEquals(a, b);

    // ── threshold ──────────────────────────────────────────────────

    // A conservative physical-machine floor is nine current-schema slots;
    // requiring one fewer tolerates one additional unavailable collector.
    // Re-evaluate this constant whenever factors or groups change.
    public const int MinimumFactors = 8;

    public static int Threshold(int n, int m)
    {
        if (n < MinimumFactors)
        {
            throw new InvalidOperationException(
                $"slhwid: need at least {MinimumFactors} enrolled factor slots, have {n}");
        }
        if (m >= n)
        {
            throw new InvalidOperationException($"slhwid: mandatory slots ({m}) must be fewer than total ({n})");
        }
        // Keep the full percentage policy explicit even though the current
        // minimum means valid new/current helpers start on the 70% branch.
        var (num, den) = n < 8 ? (4, 5) : (7, 10);
        var t = (num * n + den - 1) / den;
        return Math.Max(m + 1, Math.Min(t, n));
    }

    // ── normalization ──────────────────────────────────────────────

    private static readonly HashSet<string> Placeholders = new(StringComparer.Ordinal)
    {
        "", "none", "unknown", "default string", "to be filled by o.e.m.", "not specified", "system serial number",
    };

    public static string Normalize(string name, string raw)
    {
        var value = raw.Replace("\0", "").Trim().ToLowerInvariant();
        if (name is "mac" or "nic_identity")
        {
            value = value.Replace(":", "").Replace("-", "");
        }
        return value;
    }

    public static bool IsMissing(string value) => Placeholders.Contains(value.Trim());

    public static Dictionary<string, string> NormalizeFactors(Dictionary<string, string> raw)
    {
        var output = new Dictionary<string, string>();
        foreach (var (name, value) in raw)
        {
            var nv = Normalize(name, value);
            if (nv.Length > 0 && !IsMissing(nv))
            {
                output[name] = nv;
            }
        }
        return output;
    }

    public const byte LegacyNormVersion = 1;
    public const byte CurrentNormVersion = 2;

    private static readonly string[] LegacyFactorNames =
    [
        "slstore", "machine_guid", "product_uuid", "board_serial", "cpu_id", "disk_serial", "mac",
        "ram_total", "volume_id", "computer_name", "firmware", "gpu_id", "monitor_edid", "os_build",
    ];

    private static readonly string[] CurrentDirectFactorNames =
    [
        "slstore", "machine_guid", "cpu_id", "disk_serial", "ram_total", "volume_id", "firmware",
        "tpm_ek", "memory_modules", "nic_identity", "battery_serial",
    ];

    private static readonly (string Name, string[] Members)[] CurrentFactorGroups =
    [
        ("platform_identity", ["system_uuid", "board_serial", "system_serial", "chassis_serial"]),
        ("display_group", ["gpu_id", "monitor_edid"]),
        ("software_environment", ["computer_name", "os_build"]),
    ];

    // Factor-schema maintenance lives here. Collectors expose raw signals;
    // this function decides which signals become threshold slots. Add a direct
    // factor to CurrentDirectFactorNames, or edit CurrentFactorGroups for a
    // capped failure domain. Never remove a legacy name: schema-v1 helpers
    // need those exact inputs for recovery. Renames or semantic changes need a
    // new norm version, a recovery projection, and migration tests.
    public static Dictionary<string, string> ProjectFactors(Dictionary<string, string> raw, byte normVersion)
    {
        var output = new Dictionary<string, string>(StringComparer.Ordinal);
        if (normVersion == LegacyNormVersion)
        {
            foreach (var name in LegacyFactorNames)
            {
                if (raw.TryGetValue(name, out var value) && value.Length > 0)
                {
                    output[name] = value;
                }
            }
            return output;
        }
        if (normVersion != CurrentNormVersion)
        {
            throw new InvalidOperationException($"slhwid: unsupported factor schema {normVersion}");
        }
        foreach (var name in CurrentDirectFactorNames)
        {
            if (raw.TryGetValue(name, out var value) && value.Length > 0)
            {
                output[name] = value;
            }
        }
        foreach (var group in CurrentFactorGroups)
        {
            var value = GroupValue(group.Name, group.Members, raw);
            if (value.Length > 0)
            {
                output[group.Name] = value;
            }
        }
        return output;
    }

    private static string GroupValue(string name, string[] members, Dictionary<string, string> raw)
    {
        using var encoded = new MemoryStream();
        encoded.Write(Encoding.ASCII.GetBytes("SL-HWID-GROUP2\0"));
        encoded.Write(Encoding.ASCII.GetBytes(name));
        encoded.WriteByte(0);
        var present = false;
        foreach (var member in members)
        {
            raw.TryGetValue(member, out var value);
            present |= !string.IsNullOrEmpty(value);
            encoded.Write(Encoding.ASCII.GetBytes(member));
            encoded.WriteByte(0);
            if (!string.IsNullOrEmpty(value))
            {
                encoded.Write(Encoding.UTF8.GetBytes(value));
            }
            encoded.WriteByte(0);
        }
        return present ? Convert.ToHexString(SHA256.HashData(encoded.ToArray())).ToLowerInvariant() : "";
    }

    public static string CurrentMandatoryName(string name) => name switch
    {
        "product_uuid" or "board_serial" or "system_uuid" or "system_serial" or "chassis_serial" => "platform_identity",
        "gpu_id" or "monitor_edid" => "display_group",
        "computer_name" or "os_build" => "software_environment",
        "mac" => "nic_identity",
        _ => name,
    };

    public static HashSet<string> MapMandatoryToCurrent(IEnumerable<string> names) =>
        names.Select(CurrentMandatoryName).ToHashSet(StringComparer.Ordinal);

    // ── sharing ────────────────────────────────────────────────────

    public sealed class SlotData(string name, string value, bool mandatory)
    {
        public string Name { get; } = name;
        public string Value { get; } = value;
        public bool Mandatory { get; } = mandatory;
    }

    public static List<SlotData> SlotList(Dictionary<string, string> factors, HashSet<string> mandatory) =>
        factors.Keys.Order().Select(name => new SlotData(name, factors[name], mandatory.Contains(name))).ToList();

    public sealed record ShareResult(Dictionary<string, ulong[]> Shares, byte Salt);

    public static ShareResult BuildShares(ulong[] k, List<SlotData> slots, int t, Draw d)
    {
        byte salt = 0;
        var xs = new ulong[slots.Count];
        while (true)
        {
            for (var i = 0; i < slots.Count; i++)
            {
                xs[i] = DeriveX(slots[i].Name, slots[i].Value, salt);
            }
            if (xs.Distinct().Count() == xs.Length)
            {
                break;
            }
            salt++;
            if (salt == 255)
            {
                throw new InvalidOperationException("slhwid: x-coordinate collision loop");
            }
        }
        var coeffs = new ulong[4][];
        for (var limb = 0; limb < 4; limb++)
        {
            coeffs[limb] = new ulong[t]; // index j holds a_j; index 0 unused
            for (var j = 1; j < t; j++)
            {
                coeffs[limb][j] = d.Elem();
            }
        }
        var shares = new Dictionary<string, ulong[]>();
        for (var i = 0; i < slots.Count; i++)
        {
            var y = new ulong[4];
            for (var limb = 0; limb < 4; limb++)
            {
                ulong acc = 0;
                for (var j = t - 1; j >= 1; j--) // Horner
                {
                    acc = Addmod(Mulmod(acc, xs[i]), coeffs[limb][j]);
                }
                y[limb] = Addmod(Mulmod(acc, xs[i]), k[limb]);
            }
            shares[slots[i].Name] = y;
        }
        foreach (var row in coeffs)
        {
            Array.Clear(row); // coefficients are secret-derived
        }
        return new ShareResult(shares, salt);
    }

    // ── helper blob ────────────────────────────────────────────────

    public static byte[] SerializeHelper(Dictionary<string, ulong[]> shares, HashSet<string> mandatory, int t, byte salt, byte[] cw, byte normVersion = CurrentNormVersion)
    {
        var names = shares.Keys.Order().ToArray();
        using var payload = new MemoryStream();
        payload.WriteByte(1); // version
        payload.WriteByte(normVersion);
        payload.WriteByte(salt);
        payload.WriteByte((byte)names.Length);
        payload.WriteByte((byte)names.Count(n => mandatory.Contains(n)));
        payload.WriteByte((byte)t);
        payload.WriteByte(0); // reserved
        payload.WriteByte(0);
        foreach (var name in names)
        {
            var nameBytes = Encoding.ASCII.GetBytes(name);
            payload.WriteByte((byte)nameBytes.Length);
            payload.Write(nameBytes);
            payload.WriteByte((byte)(mandatory.Contains(name) ? 1 : 0));
            var limbBytes = new byte[8];
            foreach (var limb in shares[name])
            {
                BitConverter.TryWriteBytes(limbBytes, limb);
                payload.Write(limbBytes);
            }
        }

        using var output = new MemoryStream();
        output.Write(Encoding.ASCII.GetBytes(HelperMagic));
        Span<byte> lenBytes = stackalloc byte[4];
        BitConverter.TryWriteBytes(lenBytes, (uint)payload.Length);
        output.Write(lenBytes);
        payload.Position = 0;
        payload.CopyTo(output);
        output.Write(cw);
        var integrity = SHA256.HashData(output.ToArray());
        output.Write(integrity);
        return output.ToArray();
    }

    public sealed class HelperSlot(string name, bool mandatory, ulong[] share)
    {
        public string Name { get; } = name;
        public bool Mandatory { get; } = mandatory;
        public ulong[] Share { get; } = share;
    }

    public sealed class Helper(byte normVersion, byte salt, int threshold, List<HelperSlot> slots, byte[] checkWord)
    {
        public byte NormVersion { get; } = normVersion;
        public byte Salt { get; } = salt;
        public int Threshold { get; } = threshold;
        public List<HelperSlot> Slots { get; } = slots;
        public byte[] CheckWord { get; } = checkWord;
    }

    public static Helper ParseHelper(byte[] blob)
    {
        Exception Corrupt(string why) => new SecretSharingCorruptException($"slhwid: stored helper data is corrupt: {why}");
        if (blob.Length < 8 + 4 + 8 + 32 + 32)
        {
            throw Corrupt("truncated");
        }
        if (!Encoding.ASCII.GetBytes(HelperMagic).AsSpan().SequenceEqual(blob.AsSpan(0, 8)))
        {
            throw Corrupt("magic mismatch");
        }
        var expected = SHA256.HashData(blob.AsSpan(0, blob.Length - 32).ToArray());
        if (!CtEqual(expected, blob.AsSpan(blob.Length - 32).ToArray()))
        {
            throw Corrupt("integrity mismatch");
        }
        var payloadLen = BitConverter.ToInt32(blob, 8);
        if (12 + payloadLen + 64 != blob.Length)
        {
            throw Corrupt("length mismatch");
        }
        var body = blob.AsSpan(12, payloadLen).ToArray();
        var cw = blob.AsSpan(12 + payloadLen, 32).ToArray();
        if (body[0] != 1)
        {
            throw Corrupt($"unsupported version {body[0]}");
        }
        if (body[1] is not LegacyNormVersion and not CurrentNormVersion)
        {
            throw Corrupt($"unsupported factor schema {body[1]}");
        }
        var n = body[3];
        var helper = new Helper(body[1], body[2], body[5], new List<HelperSlot>(), cw);
        var offset = 8;
        var seen = new HashSet<string>();
        for (var i = 0; i < n; i++)
        {
            if (offset + 1 > body.Length)
            {
                throw Corrupt("slot truncated");
            }
            var nameLen = body[offset];
            if (nameLen == 0 || offset + 1 + nameLen + 1 + 32 > body.Length)
            {
                throw Corrupt("slot truncated");
            }
            var name = Encoding.ASCII.GetString(body, offset + 1, nameLen);
            if (!seen.Add(name))
            {
                throw Corrupt($"duplicate slot {name}");
            }
            var mandatory = (body[offset + 1 + nameLen] & 1) == 1;
            var share = new ulong[4];
            for (var limb = 0; limb < 4; limb++)
            {
                share[limb] = BitConverter.ToUInt64(body, offset + 2 + nameLen + limb * 8);
                if (share[limb] >= Prime)
                {
                    throw Corrupt("share limb out of range");
                }
            }
            helper.Slots.Add(new HelperSlot(name, mandatory, share));
            offset += 2 + nameLen + 32;
        }
        if (offset != body.Length)
        {
            throw Corrupt("trailing bytes");
        }
        return helper;
    }

    // ── recovery ───────────────────────────────────────────────────

    public sealed record Point(string Name, ulong X, ulong[] Share);

    public sealed class RecoverResult
    {
        public bool Ok;
        public string Reason = ""; // drift | mandatory | corrupt
        public ulong[]? Key;
        public string Hwid = "";
        public List<string> Live = [];
        public List<string> Dead = [];
        public bool Pending;
        public int Present;
        public int Needed;
        public List<string> Missing = [];
    }

    private static ulong LagrangeAtZero(Point[] points, int limb)
    {
        ulong total = 0;
        for (var j = 0; j < points.Length; j++)
        {
            ulong num = 1, den = 1;
            for (var k = 0; k < points.Length; k++)
            {
                if (k == j)
                {
                    continue;
                }
                num = Mulmod(num, points[k].X);
                den = Mulmod(den, Submod(points[k].X, points[j].X));
            }
            total = Addmod(total, Mulmod(points[j].Share[limb], Mulmod(num, Invmod(den))));
        }
        return total;
    }

    private static ulong EvaluateAt(Point[] points, int limb, ulong xq)
    {
        ulong total = 0;
        for (var j = 0; j < points.Length; j++)
        {
            ulong num = 1, den = 1;
            for (var k = 0; k < points.Length; k++)
            {
                if (k == j)
                {
                    continue;
                }
                num = Mulmod(num, Submod(xq, points[k].X));
                den = Mulmod(den, Submod(points[j].X, points[k].X));
            }
            total = Addmod(total, Mulmod(points[j].Share[limb], Mulmod(num, Invmod(den))));
        }
        return total;
    }

    public static ulong[] KeyFromPoints(Point[] points)
    {
        var k = new ulong[4];
        for (var limb = 0; limb < 4; limb++)
        {
            k[limb] = LagrangeAtZero(points, limb);
        }
        return k;
    }

    // Searches size-t subsets containing every mandatory candidate, in
    // lexicographic order; mandatory slots are in every subset: a wrong
    // mandatory factor cannot be routed around (hard lock). The sweep is
    // exhaustive: neither intermediate failures nor a match truncate it, so
    // the amount of work done does not signal which factors survived
    // (side-channel resistance).
    private static Point[]? FindRecoveringSubset(Point[] mandatory, Point[] optional, int t, byte[] cw)
    {
        var need = Math.Max(0, t - mandatory.Length);
        if (need > optional.Length)
        {
            return null;
        }
        var result = new Point[t];
        mandatory.CopyTo(result, 0);
        Point[]? match = null;
        void Search(int start, int depth)
        {
            if (depth == need)
            {
                if (match is null && CtEqual(CheckWord(KeyFromPoints(result)), cw))
                {
                    match = (Point[])result.Clone();
                }
                return;
            }
            for (var i = start; i <= optional.Length - (need - depth); i++)
            {
                result[mandatory.Length + depth] = optional[i];
                Search(i + 1, depth + 1);
            }
        }
        Search(0, 0);
        return match;
    }

    private static bool IsMandatorySlot(Helper helper, string name) =>
        helper.Slots.Any(s => s.Name == name && s.Mandatory);

    public static RecoverResult RecoverCore(byte[] blob, Dictionary<string, string> factors)
    {
        var result = new RecoverResult();
        Helper helper;
        try
        {
            helper = ParseHelper(blob);
        }
        catch (SecretSharingCorruptException)
        {
            result.Reason = "corrupt";
            return result;
        }
        var t = helper.Threshold;

        var mandatory = new List<Point>();
        var optional = new List<Point>();
        var missingMandatory = new List<string>();
        var present = 0;
        foreach (var slot in helper.Slots) // slots are stored sorted by name
        {
            if (!factors.TryGetValue(slot.Name, out var value) || value.Length == 0)
            {
                if (slot.Mandatory)
                {
                    missingMandatory.Add(slot.Name);
                }
                continue;
            }
            present++;
            var point = new Point(slot.Name, DeriveX(slot.Name, value, helper.Salt), slot.Share);
            if (slot.Mandatory)
            {
                mandatory.Add(point);
            }
            else
            {
                optional.Add(point);
            }
        }
        // The sweep runs to completion regardless of absences or failures
        // (constant-work shape); the hard-locked mandatory verdict is applied
        // afterwards and any accidental match is discarded.
        var found = FindRecoveringSubset(mandatory.ToArray(), optional.ToArray(), t, helper.CheckWord);
        if (missingMandatory.Count > 0)
        {
            result.Reason = "mandatory";
            result.Present = present;
            result.Needed = t;
            result.Missing = missingMandatory;
            return result;
        }
        if (found is null)
        {
            // Diagnostic: if dropping one mandatory slot lets the rest of
            // the machine recover, that mandatory factor was changed
            // (intentional tampering) rather than the machine having drifted.
            // Every mandatory slot is tested (no early exit); the first
            // culprit in stored order wins.
            string? culprit = null;
            foreach (var ms in helper.Slots.Where(s => s.Mandatory))
            {
                var merged = mandatory.Concat(optional).Where(p => p.Name != ms.Name).ToList();
                var mand2 = merged.Where(p => IsMandatorySlot(helper, p.Name)).ToArray();
                var opt2 = merged.Where(p => !IsMandatorySlot(helper, p.Name)).ToArray();
                if (culprit is null && FindRecoveringSubset(mand2, opt2, t, helper.CheckWord) is not null)
                {
                    culprit = ms.Name;
                }
            }
            if (culprit is not null)
            {
                result.Reason = "mandatory";
                result.Present = present;
                result.Needed = t;
                result.Missing = [culprit];
                return result;
            }
            result.Reason = "drift";
            result.Present = present;
            result.Needed = t;
            return result;
        }

        var k = KeyFromPoints(found);
        var inSubset = found.Select(p => p.Name).ToHashSet();
        var live = new List<string>();
        var dead = new List<string>();
        foreach (var slot in helper.Slots)
        {
            if (inSubset.Contains(slot.Name))
            {
                live.Add(slot.Name);
                continue;
            }
            if (!factors.TryGetValue(slot.Name, out var value) || value.Length == 0)
            {
                dead.Add(slot.Name);
                continue;
            }
            var xq = DeriveX(slot.Name, value, helper.Salt);
            var onCurve = true;
            for (var limb = 0; limb < 4; limb++)
            {
                if (EvaluateAt(found, limb, xq) != slot.Share[limb])
                {
                    onCurve = false;
                    break;
                }
            }
            (onCurve ? live : dead).Add(slot.Name);
        }
        live.Sort(StringComparer.Ordinal);
        dead.Sort(StringComparer.Ordinal);
        result.Ok = true;
        result.Key = k;
        result.Hwid = HwidOf(k);
        result.Live = live;
        result.Dead = dead;
        result.Pending = dead.Count > 0;
        return result;
    }

    // Re-shares k over the current factors; (null, false) when skipped.
    public static (byte[]? Blob, bool Written) RefreshCore(ulong[] k, Dictionary<string, string> factors, HashSet<string> mandatory, Draw d)
    {
        var slots = SlotList(factors, mandatory);
        var m = slots.Count(s => s.Mandatory);
        int t;
        try
        {
            t = Threshold(slots.Count, m);
        }
        catch (InvalidOperationException)
        {
            return (null, false);
        }
        var (shares, salt) = BuildShares(k, slots, t, d);
        var blob = SerializeHelper(shares, mandatory, t, salt, CheckWord(k));
        return (blob, true);
    }
}

// Replays a byte source (the CSPRNG in production, fixed streams in tests)
// as consecutive 8-byte little-endian draws.
internal sealed class Draw(Func<int, byte[]> source)
{
    private readonly Func<int, byte[]> _source = source;

    public ulong Elem()
    {
        var chunk = _source(8);
        if (chunk.Length != 8)
        {
            throw new InvalidOperationException("slhwid: randomness exhausted");
        }
        return BitConverter.ToUInt64(chunk, 0) % SLHwidCore.Prime;
    }
}

internal sealed class FixedDraw
{
    public static Func<int, byte[]> Source(byte[] data)
    {
        var position = 0;
        return n =>
        {
            var chunk = data.Skip(position).Take(n).ToArray();
            position += n;
            return chunk;
        };
    }
}

// Exceptions surfaced by the module.
internal sealed class SecretSharingCorruptException(string message) : Exception(message);
