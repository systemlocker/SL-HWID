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
        var slotBytes = Encoding.ASCII.GetBytes(slot);
        var valueBytes = Encoding.UTF8.GetBytes(value);
        // Length counts encoded bytes, not UTF-16 code units. Hardware strings
        // can legitimately contain non-ASCII characters.
        var input = new byte[12 + slotBytes.Length + valueBytes.Length]; // label + \0 + salt + \0 + slot + \0 + value
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
        Put(slotBytes);
        input[offset++] = 0;
        Put(valueBytes);
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
        "", "0", "none", "unknown", "default", "default string", "to be filled by o.e.m.",
        "not specified", "not available", "not applicable", "not present", "n/a", "na", "null",
        "system serial number", "asset tag", "no asset tag", "123456789", "0123456789", "example",
    };

    private static readonly HashSet<string> IdentifierFactors = new(StringComparer.Ordinal)
    {
        "machine_guid", "product_uuid", "system_uuid", "board_serial", "system_serial", "chassis_serial",
        "disk_serial", "volume_id", "tpm_ek", "memory_modules", "nic_identity", "battery_serial", "monitor_edid",
    };

    public static string Normalize(string name, string raw)
    {
        var chars = raw.Replace("\0", "").Trim().ToCharArray();
        // The wire contract specifies ASCII lowercase. Unicode hardware text
        // must otherwise remain byte-stable across native and managed clients.
        for (var i = 0; i < chars.Length; i++)
        {
            if (chars[i] is >= 'A' and <= 'Z')
            {
                chars[i] = (char)(chars[i] + ('a' - 'A'));
            }
        }
        var value = new string(chars);
        if (name is "mac" or "nic_identity")
        {
            value = value.Replace(":", "").Replace("-", "");
        }
        return value;
    }

    public static bool IsMissing(string value) => Placeholders.Contains(value.Trim());

    public static bool IsSaneFactor(string name, string value)
    {
        if (value.Length == 0 || Encoding.UTF8.GetByteCount(value) > 4096 || IsMissing(value))
        {
            return false;
        }
        if (name == "ram_total")
        {
            // All collectors report bytes. 128 MiB is deliberately far below
            // supported desktop/server hardware while rejecting unit mistakes
            // such as a KiB value being labeled as bytes.
            return value.All(char.IsAsciiDigit)
                && ulong.TryParse(value, out var bytes)
                && bytes >= 128UL * 1024 * 1024;
        }
        if (name is "machine_guid" or "product_uuid" or "system_uuid")
        {
            return IsUuidLike(value);
        }
        if (name == "slstore")
        {
            return value.Length == 64 && value.All(Uri.IsHexDigit) && !IsDegenerateIdentifier(value);
        }
        if (name == "tpm_ek" && (value.Length != 64 || !value.All(Uri.IsHexDigit)))
        {
            return false;
        }
        if (name is "mac" or "nic_identity")
        {
            return value.Split('|').All(part => part.Length == 12 && part.All(Uri.IsHexDigit)
                && !IsDegenerateIdentifier(part));
        }
        if (IdentifierFactors.Contains(name))
        {
            return value.Split('|').All(part => !IsMissing(part) && !IsDegenerateIdentifier(part));
        }
        return true;
    }

    private static bool IsUuidLike(string value)
    {
        var hyphensValid = value.Length == 32 || value.Length == 36
            && value[8] == '-' && value[13] == '-' && value[18] == '-' && value[23] == '-';
        var compact = value.Replace("-", "");
        return hyphensValid && compact.Length == 32 && compact.All(Uri.IsHexDigit)
            && !IsDegenerateIdentifier(compact)
            && compact != "12345678123412341234123456789abc";
    }

    private static bool IsDegenerateIdentifier(string value)
    {
        var compact = new string(value.Where(char.IsLetterOrDigit).ToArray());
        return compact.Length >= 4
            && (compact.All(c => c == '0') || compact.All(c => c == 'f'));
    }

    public static Dictionary<string, string> NormalizeFactors(Dictionary<string, string> raw)
    {
        var output = new Dictionary<string, string>();
        foreach (var (name, value) in raw)
        {
            var nv = Normalize(name, value);
            if (IsSaneFactor(name, nv))
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
        // A valid helper is currently under 1 KiB. Bound the untrusted local
        // blob before hashing/parsing so a writable store cannot force large
        // allocations or an unbounded recovery search.
        if (blob.Length > 4096)
        {
            throw Corrupt("oversized");
        }
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
        var payloadLen = BitConverter.ToUInt32(blob, 8);
        if (payloadLen < 8 || payloadLen > 4096 || 12UL + payloadLen + 64UL != (ulong)blob.Length)
        {
            throw Corrupt("length mismatch");
        }
        var body = blob.AsSpan(12, checked((int)payloadLen)).ToArray();
        var cw = blob.AsSpan(12 + checked((int)payloadLen), 32).ToArray();
        if (body[0] != 1)
        {
            throw Corrupt($"unsupported version {body[0]}");
        }
        if (body[1] is not LegacyNormVersion and not CurrentNormVersion)
        {
            throw Corrupt($"unsupported factor schema {body[1]}");
        }
        if (body[6] != 0 || body[7] != 0)
        {
            throw Corrupt("reserved header bits set");
        }
        var allowedNames = body[1] == LegacyNormVersion
            ? LegacyFactorNames.ToHashSet(StringComparer.Ordinal)
            : CurrentDirectFactorNames.Concat(CurrentFactorGroups.Select(g => g.Name)).ToHashSet(StringComparer.Ordinal);
        var n = body[3];
        var mandatoryHeader = body[4];
        var threshold = body[5];
        if (n == 0 || n > allowedNames.Count)
        {
            throw Corrupt("invalid slot count");
        }
        if (threshold == 0 || threshold > n || mandatoryHeader == 0 || mandatoryHeader >= threshold)
        {
            throw Corrupt("invalid threshold");
        }
        var helper = new Helper(body[1], body[2], threshold, new List<HelperSlot>(), cw);
        var offset = 8;
        var seen = new HashSet<string>();
        string? previousName = null;
        var actualMandatory = 0;
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
            if (!allowedNames.Contains(name))
            {
                throw Corrupt($"invalid slot {name}");
            }
            if (!seen.Add(name) || previousName is not null && string.CompareOrdinal(previousName, name) >= 0)
            {
                throw Corrupt($"duplicate or unsorted slot {name}");
            }
            previousName = name;
            var flags = body[offset + 1 + nameLen];
            if (flags is not 0 and not 1)
            {
                throw Corrupt("invalid slot flags");
            }
            var mandatory = flags == 1;
            if (mandatory)
            {
                actualMandatory++;
            }
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
        if (actualMandatory != mandatoryHeader)
        {
            throw Corrupt("mandatory count mismatch");
        }
        if (!helper.Slots.Any(slot => slot.Name == "slstore" && slot.Mandatory))
        {
            throw Corrupt("mandatory slstore missing");
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
