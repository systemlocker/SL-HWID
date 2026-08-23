#pragma once

// Internal SL-HWID surface shared between the implementation translation
// units and the test suite. Not installed and not part of the ABI.

#include "slhwid/slhwid.hpp"

#include <array>
#include <cstdint>
#include <functional>
#include <map>
#include <memory>
#include <optional>
#include <set>
#include <string>
#include <vector>

namespace slhwid::detail
{
    constexpr std::uint64_t kPrime = (std::uint64_t(1) << 61) - 1;

    using Key = std::array<std::uint64_t, 4>;
    using Share = Key;

    std::uint64_t addmod(std::uint64_t a, std::uint64_t b);
    std::uint64_t submod(std::uint64_t a, std::uint64_t b);
    std::uint64_t mulmod(std::uint64_t a, std::uint64_t b);
    std::uint64_t invmod(std::uint64_t a);

    std::uint64_t deriveX(const std::string &slot, const std::string &value, std::uint8_t salt);
    std::vector<unsigned char> keyBytes(const Key &k);
    std::vector<unsigned char> checkWord(const Key &k);
    std::string hwidOf(const Key &k);
    bool ctEqual(const std::vector<unsigned char> &a, const std::vector<unsigned char> &b);
    std::vector<unsigned char> sha256(const std::vector<unsigned char> &data);
    std::string base64UrlEncode(const std::vector<unsigned char> &data);
    bool randomBytes(unsigned char *out, std::size_t n);

    // Threshold: 80% above ten factors, else 70%; at least five enrolled
    // factors; never below mandatory+1. Returns 0 on refusal.
    int threshold(int n, int m);

    std::string normalize(const std::string &name, const std::string &raw);
    bool isMissing(const std::string &value);
    std::map<std::string, std::string> normalizeFactors(const std::map<std::string, std::string> &raw);

    struct SlotData
    {
        std::string name;
        std::string value;
        bool mandatory = false;
    };
    std::vector<SlotData> slotList(const std::map<std::string, std::string> &factors, const std::set<std::string> &mandatory);

    /// A randomness source hands out n bytes; production uses the CSPRNG,
    /// tests replay fixed streams.
    using Source = std::function<bool(unsigned char *, std::size_t)>;

    struct Draw
    {
        explicit Draw(Source source) : source_(std::move(source)) {}
        std::uint64_t elem(); // throws std::runtime_error when exhausted

    private:
        Source source_;
    };

    struct ShareResult
    {
        std::map<std::string, Share> shares;
        std::uint8_t salt = 0;
    };
    ShareResult buildShares(const Key &k, const std::vector<SlotData> &slots, int t, Draw &draw);

    struct HelperSlot
    {
        std::string name;
        bool mandatory = false;
        Share share{};
    };
    struct Helper
    {
        std::uint8_t salt = 0;
        int threshold = 0;
        std::vector<HelperSlot> slots; // stored sorted by name
        std::vector<unsigned char> checkWord;
    };

    std::vector<unsigned char> serializeHelper(const std::map<std::string, Share> &shares,
                                               const std::set<std::string> &mandatory,
                                               int t, std::uint8_t salt,
                                               const std::vector<unsigned char> &cw);
    // Throws a corrupt-typed std::runtime_error on bad input.
    Helper parseHelper(const std::vector<unsigned char> &blob);
    bool isCorruptError(const std::exception &error);

    struct RecoverResult
    {
        bool ok = false;
        std::string reason; // "drift" | "mandatory" | "corrupt"
        Key key{};
        std::string hwid;
        std::vector<std::string> live;
        std::vector<std::string> dead;
        bool pending = false;
        int present = 0;
        int needed = 0;
        std::vector<std::string> missing;
    };
    RecoverResult recoverCore(const std::vector<unsigned char> &blob, const std::map<std::string, std::string> &factors);

    struct RefreshResult
    {
        std::vector<unsigned char> blob;
        bool written = false;
    };
    RefreshResult refreshCore(const Key &k,
                              const std::map<std::string, std::string> &factors,
                              const std::set<std::string> &mandatory,
                              Draw &draw);

    /// Keyed byte storage; production maps keys to registry values or files.
    class Store
    {
    public:
        virtual ~Store() = default;

        /// Returns nullopt when the key is absent; a failed read with
        /// `error` set is a hard failure.
        struct Read
        {
            std::optional<std::vector<unsigned char>> data;
            std::string error;
        };
        virtual Read read(const std::string &key) = 0;
        virtual bool write(const std::string &key, const std::vector<unsigned char> &data, std::string &error) = 0;
        // Test stores have no backing path and deliberately return empty.
        virtual std::string lockDirectory() const { return ""; }
    };

    std::shared_ptr<Store> defaultStore(const std::string &overridePath, std::string &error);
    bool acquireStorageLock(const std::string &directory, std::function<void()> &release, std::string &error);
    std::map<std::string, std::string> collectFactors(std::string &error);

    struct SessionState
    {
        Key key{};
        bool hasKey = false;
        bool committed = false;
        std::map<std::string, std::string> factors;
        std::set<std::string> mandatory;
        std::shared_ptr<Store> store;
        Source source;
        std::vector<unsigned char> expectedHelper;
    };

    class ScopedUnlock
    {
    public:
        explicit ScopedUnlock(std::function<void()> release) : release_(std::move(release)) {}
        ~ScopedUnlock()
        {
            if (release_)
                release_();
        }

        ScopedUnlock(const ScopedUnlock &) = delete;
        ScopedUnlock &operator=(const ScopedUnlock &) = delete;

    private:
        std::function<void()> release_;
    };

    Result<Session> prepareWith(const Options &options,
                                const std::function<std::map<std::string, std::string>()> &collect,
                                const Source &source,
                                const std::shared_ptr<Store> &store);

    /// The production randomness source (platform CSPRNG).
    Source defaultRandomSource();

    void secureWipe(void *data, std::size_t length);
    std::string toLowerHex(const std::vector<unsigned char> &data);
}
