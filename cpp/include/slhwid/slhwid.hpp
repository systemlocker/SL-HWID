#pragma once

// SL-HWID — a fault-tolerant, cross-platform hardware fingerprint.
//
// A random 244-bit key is shared across 14 hardware factors with a
// threshold scheme; the identifier is a domain-separated hash of that key.
// Any two factors can fail or change without changing the identifier, and
// drifted factors are re-absorbed by committing after each successful
// authorization. The module's own persisted value (slstore) is hard-locked:
// changing or deleting it always requires re-activation.
//
// Storage formats are byte-compatible with the C# implementation. MIT
// licensed; see the repository LICENSE.

#include <memory>
#include <optional>
#include <string>
#include <vector>

#if defined(_WIN32) && defined(SLHWID_SHARED)
#ifdef SLHWID_BUILDING
#define SLHWID_API __declspec(dllexport)
#else
#define SLHWID_API __declspec(dllimport)
#endif
#else
#define SLHWID_API
#endif

namespace slhwid
{
    enum class ErrorKind
    {
        Configuration,
        LocalFailure,
    };

    struct Error
    {
        ErrorKind kind = ErrorKind::LocalFailure;
        std::string message;
    };

    template <class T>
    class Result
    {
    public:
        Result(T value) : value_(std::move(value)) {}

        static Result fail(ErrorKind kind, std::string message)
        {
            Result result;
            result.error_ = Error{kind, std::move(message)};
            return result;
        }

        explicit operator bool() const noexcept { return value_.has_value(); }
        bool ok() const noexcept { return value_.has_value(); }

        T &operator*() { return *value_; }
        const T &operator*() const { return *value_; }
        T *operator->() { return &*value_; }
        const T *operator->() const { return &*value_; }

        const Error &error() const noexcept { return *error_; }

    private:
        Result() = default;
        std::optional<T> value_;
        std::optional<Error> error_;
    };

    /// Configuration for one prepare call.
    struct Options
    {
        /// Optionally redirects storage to a directory (files on every
        /// platform). Empty uses the platform default: the registry on
        /// Windows, a per-user application-support directory elsewhere.
        std::string storePath;

        /// Names additional hard-locked slots beyond the default "slstore"
        /// (for example, "machine_guid").
        std::vector<std::string> extraMandatory;

        /// Discards shared device helper data and enrolls a fresh key (new
        /// identifier). This affects all applications sharing the store; the
        /// application must then re-authorize the machine.
        bool forceReenroll = false;
    };

    /// One prepared SL-HWID. hwid() is available immediately; commit()
    /// persists a re-centered share set and must only be called after the
    /// consumer (typically a licensing server) accepted the identifier.
    class SLHWID_API Session
    {
    public:
        Session(std::string hwid,
                bool freshlyEnrolled,
                std::vector<std::string> driftedSlots,
                bool pendingRefresh,
                std::shared_ptr<void> state);
        ~Session();

        Session(Session &&) = default;
        Session(const Session &) = delete;
        Session &operator=(const Session &) = delete;

        /// The identifier (43 characters, unpadded base64url).
        const std::string &hwid() const noexcept;

        /// Whether this session created a key the machine never had.
        bool freshlyEnrolled() const noexcept;

        /// Enrolled slots that were dead at prepare time.
        const std::vector<std::string> &driftedSlots() const noexcept;

        /// Whether any slot was dead (commit will re-center).
        bool pendingRefresh() const noexcept;

        /// Re-shares the recovered key over the hardware observed at prepare
        /// time and persists the new helper data. Failures are non-fatal:
        /// the next launch re-derives everything.
        void commit() noexcept;

    private:
        std::string hwid_;
        bool freshlyEnrolled_;
        std::vector<std::string> driftedSlots_;
        bool pendingRefresh_;
        std::shared_ptr<void> state_; // internal key/store wiring; wiped on commit
    };

    /// Collects factors and recovers (or enrolls) the SL-HWID. Enrollment
    /// persists immediately; a recovered session persists nothing until
    /// Session::commit.
    SLHWID_API Result<Session> prepare(const Options &options);
}
