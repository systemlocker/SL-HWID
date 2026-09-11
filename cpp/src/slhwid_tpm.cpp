#include "slhwid_internal.hpp"

#if defined(_WIN32)
#include <windows.h>
#include <ncrypt.h>
#include <wincrypt.h>
#endif

namespace slhwid::detail
{
    std::optional<std::string> hashTpmPublicBlob(const std::vector<unsigned char> &blob)
    {
#if defined(_WIN32)
        constexpr std::size_t limit = 8192;
        if (blob.size() < 24 || blob.size() > limit)
            return std::nullopt;
        const auto word = [&blob](std::size_t offset) -> std::uint32_t {
            return std::uint32_t(blob[offset]) | (std::uint32_t(blob[offset + 1]) << 8) |
                   (std::uint32_t(blob[offset + 2]) << 16) | (std::uint32_t(blob[offset + 3]) << 24);
        };
        const auto exponent = word(8);
        const auto modulus = word(12);
        // The Windows encoder has no input-length parameter. Check every
        // embedded length before passing the public RSA blob to it.
        if (word(0) != 0x31415352 || exponent == 0 || modulus == 0 ||
            std::uint64_t(24) + exponent + modulus != blob.size() ||
            word(4) != std::uint64_t(modulus) * 8 || word(16) != 0 || word(20) != 0)
            return std::nullopt;

        // Match Get-TpmEndorsementKeyInfo: SHA-256 of ASN.1 RSAPublicKey,
        // not the CNG blob or SubjectPublicKeyInfo. Existing TPM shares
        // therefore keep their exact value when collection becomes native.
        DWORD size = 0;
        if (!CryptEncodeObjectEx(X509_ASN_ENCODING, CNG_RSA_PUBLIC_KEY_BLOB,
                                 blob.data(), 0, nullptr, nullptr, &size) || size == 0 || size > limit)
            return std::nullopt;
        std::vector<unsigned char> encoded(size);
        if (!CryptEncodeObjectEx(X509_ASN_ENCODING, CNG_RSA_PUBLIC_KEY_BLOB,
                                 blob.data(), 0, nullptr, encoded.data(), &size) || size == 0 || size > encoded.size())
            return std::nullopt;
        encoded.resize(size);
        return toLowerHex(sha256(encoded));
#else
        (void)blob;
        return std::nullopt;
#endif
    }

    std::optional<std::string> nativeTpmFactor()
    {
#if defined(_WIN32)
        NCRYPT_PROV_HANDLE provider = 0;
        if (NCryptOpenStorageProvider(&provider, MS_PLATFORM_CRYPTO_PROVIDER, 0) != ERROR_SUCCESS)
            return std::nullopt;
        // This only reads the public endorsement identity. Silent property
        // queries never ask the application user to elevate or interact.
        struct CloseProvider
        {
            NCRYPT_PROV_HANDLE handle;
            ~CloseProvider() { NCryptFreeObject(handle); }
        } close{provider};
        DWORD size = 0;
        if (NCryptGetProperty(provider, NCRYPT_PCP_EKPUB_PROPERTY, nullptr, 0, &size, NCRYPT_SILENT_FLAG) != ERROR_SUCCESS ||
            size < 24 || size > 8192)
            return std::nullopt;
        std::vector<unsigned char> blob(size);
        DWORD written = 0;
        if (NCryptGetProperty(provider, NCRYPT_PCP_EKPUB_PROPERTY, blob.data(), size, &written, NCRYPT_SILENT_FLAG) != ERROR_SUCCESS ||
            written < 24 || written > blob.size())
            return std::nullopt;
        blob.resize(written);
        return hashTpmPublicBlob(blob);
#else
        return std::nullopt;
#endif
    }
}
