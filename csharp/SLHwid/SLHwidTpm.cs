using System.Buffers.Binary;
using System.Runtime.InteropServices;
using System.Security.Cryptography;

namespace SLHwid;

internal static class SLHwidTpm
{
    private const int Limit = 8192;
    private const int Silent = 0x40;

    [DllImport("ncrypt.dll", CharSet = CharSet.Unicode)]
    private static extern int NCryptOpenStorageProvider(out nint provider, string name, int flags);
    [DllImport("ncrypt.dll", CharSet = CharSet.Unicode)]
    private static extern int NCryptGetProperty(nint provider, string name, byte[]? output, int capacity, out int written, int flags);
    [DllImport("ncrypt.dll")]
    private static extern int NCryptFreeObject(nint provider);
    [DllImport("crypt32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CryptEncodeObjectEx(int encoding, nint type, byte[] input, int flags,
        nint allocation, byte[]? output, ref int size);

    internal static string? CollectNative(out string detail)
    {
        detail = "Native TPM collection is unavailable on this platform.";
        if (!OperatingSystem.IsWindows()) return null;
        nint provider = 0;
        try
        {
            var status = NCryptOpenStorageProvider(out provider, "Microsoft Platform Crypto Provider", 0);
            if (status != 0) { detail = $"Native TPM provider: 0x{status:X8}."; return null; }
            status = NCryptGetProperty(provider, "PCP_EKPUB", null, 0, out var size, Silent);
            if (status != 0) { detail = $"Native TPM public-key size query: 0x{status:X8}."; return null; }
            if (size is < 24 or > Limit) { detail = "Native TPM public-key size is invalid."; return null; }
            var blob = new byte[size];
            status = NCryptGetProperty(provider, "PCP_EKPUB", blob, blob.Length, out var written, Silent);
            if (status != 0) { detail = $"Native TPM public-key read: 0x{status:X8}."; return null; }
            if (written < 24 || written > blob.Length) { detail = "Native TPM public-key read returned an invalid size."; return null; }
            var hash = HashPublicBlob(blob.AsSpan(0, written).ToArray());
            detail = hash is null ? "Native TPM public-key encoding is unsupported or invalid." :
                "Native Platform Crypto Provider; SHA-256 fingerprint compatible with PowerShell.";
            return hash;
        }
        catch (Exception error) { detail = $"Native TPM query failed ({error.GetType().Name}, 0x{error.HResult:X8})."; return null; }
        finally { if (provider != 0) NCryptFreeObject(provider); }
    }

    internal static string? HashPublicBlob(byte[] blob)
    {
        if (!OperatingSystem.IsWindows() || blob.Length is < 24 or > Limit) return null;
        uint Word(int offset) => BinaryPrimitives.ReadUInt32LittleEndian(blob.AsSpan(offset, 4));
        // CryptEncodeObjectEx consumes a CNG RSA public blob without a length
        // argument. Validate its internal lengths before handing it to Windows.
        var exponent = Word(8);
        var modulus = Word(12);
        if (Word(0) != 0x31415352 || exponent == 0 || modulus == 0 ||
            24UL + exponent + modulus != (ulong)blob.Length ||
            Word(4) != modulus * 8UL || Word(16) != 0 || Word(20) != 0) return null;

        // PowerShell's Get-TpmEndorsementKeyInfo hashes this exact ASN.1
        // RSAPublicKey encoding, not the CNG blob or SubjectPublicKeyInfo.
        // Keeping its fingerprint lets existing TPM shares recover natively.
        var size = 0;
        if (!CryptEncodeObjectEx(1, 72, blob, 0, 0, null, ref size) || size is <= 0 or > Limit) return null;
        var encoded = new byte[size];
        if (!CryptEncodeObjectEx(1, 72, blob, 0, 0, encoded, ref size) || size <= 0 || size > encoded.Length) return null;
        return Convert.ToHexString(SHA256.HashData(encoded.AsSpan(0, size))).ToLowerInvariant();
    }
}
