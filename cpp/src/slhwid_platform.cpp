#define _CRT_SECURE_NO_WARNINGS
// SL-HWID platform layer: default storage (one coherently selected Windows
// registry hive; owner-only files elsewhere) and factor collectors. Every source
// degrades gracefully — a missing source just leaves the slot absent, which
// the threshold scheme absorbs.

#include "slhwid_internal.hpp"

#include <algorithm>
#include <cctype>
#include <chrono>
#include <ctime>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <iterator>
#include <optional>
#include <regex>
#include <sstream>
#include <sys/stat.h>
#include <thread>

#if defined(_WIN32)
#include <winsock2.h>
#include <windows.h>
#include <bcrypt.h>
#include <iphlpapi.h>
#include <winioctl.h>
#else
#include <cerrno>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#if defined(__linux__)
#include <filesystem>
#include <sys/random.h>
#endif
#endif

namespace slhwid::detail
{
    RegistryRootSelection selectRegistryRoot(bool machineHelper, bool machineSlstore,
                                             bool userHelper, bool userSlstore)
    {
        if (machineHelper && machineSlstore)
            return RegistryRootSelection::machine;
        if (userHelper && userSlstore)
            return RegistryRootSelection::user;
        if (machineHelper)
            return RegistryRootSelection::machine;
        if (userHelper)
            return RegistryRootSelection::user;
        if (machineSlstore)
            return RegistryRootSelection::machine;
        if (userSlstore)
            return RegistryRootSelection::user;
        return RegistryRootSelection::none;
    }

    std::optional<std::string> parseRawSmbiosUuid(const std::vector<unsigned char> &raw)
    {
        if (raw.size() < 8)
            return std::nullopt;
        const std::uint32_t tableLength =
            static_cast<std::uint32_t>(raw[4]) | (static_cast<std::uint32_t>(raw[5]) << 8) |
            (static_cast<std::uint32_t>(raw[6]) << 16) | (static_cast<std::uint32_t>(raw[7]) << 24);
        if (tableLength > raw.size() - 8)
            return std::nullopt;
        const std::size_t end = 8 + tableLength;
        for (std::size_t offset = 8; offset + 4 <= end;)
        {
            const unsigned char type = raw[offset];
            const std::size_t formattedLength = raw[offset + 1];
            if (formattedLength < 4 || offset + formattedLength > end)
                return std::nullopt;
            if (type == 1 && formattedLength >= 24)
            {
                const unsigned char *uuid = raw.data() + offset + 8;
                const bool allZero = std::all_of(uuid, uuid + 16, [](unsigned char b) { return b == 0; });
                const bool allOnes = std::all_of(uuid, uuid + 16, [](unsigned char b) { return b == 0xff; });
                if (allZero || allOnes)
                    return std::nullopt;
                const bool littleEndianFields = raw[1] > 2 || (raw[1] == 2 && raw[2] >= 6);
                const int a0 = littleEndianFields ? 3 : 0;
                const int a1 = littleEndianFields ? 2 : 1;
                const int a2 = littleEndianFields ? 1 : 2;
                const int a3 = littleEndianFields ? 0 : 3;
                const int b0 = littleEndianFields ? 5 : 4;
                const int b1 = littleEndianFields ? 4 : 5;
                const int c0 = littleEndianFields ? 7 : 6;
                const int c1 = littleEndianFields ? 6 : 7;
                char formatted[37]{};
                std::snprintf(formatted, sizeof(formatted),
                              "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
                              uuid[a0], uuid[a1], uuid[a2], uuid[a3], uuid[b0], uuid[b1],
                              uuid[c0], uuid[c1], uuid[8], uuid[9], uuid[10], uuid[11],
                              uuid[12], uuid[13], uuid[14], uuid[15]);
                return std::string(formatted);
            }
            std::size_t next = offset + formattedLength;
            while (next + 1 < end && (raw[next] != 0 || raw[next + 1] != 0))
                ++next;
            if (next + 1 >= end)
                return std::nullopt;
            offset = next + 2;
            if (type == 127)
                break;
        }
        return std::nullopt;
    }

    std::optional<std::string> parseStorageDescriptorSerial(
        const std::vector<unsigned char> &descriptor, std::size_t returned)
    {
        if (returned < 36 || returned > descriptor.size())
            return std::nullopt;
        const std::uint32_t offset =
            static_cast<std::uint32_t>(descriptor[24]) | (static_cast<std::uint32_t>(descriptor[25]) << 8) |
            (static_cast<std::uint32_t>(descriptor[26]) << 16) | (static_cast<std::uint32_t>(descriptor[27]) << 24);
        if (offset == 0 || offset >= returned)
            return std::nullopt;
        const char *begin = reinterpret_cast<const char *>(descriptor.data() + offset);
        const char *end = begin;
        const char *limit = reinterpret_cast<const char *>(descriptor.data() + returned);
        while (end < limit && *end != '\0')
            ++end;
        std::string serial(begin, end);
        std::size_t first = 0;
        std::size_t last = serial.size();
        while (first < last && std::isspace(static_cast<unsigned char>(serial[first])))
            ++first;
        while (last > first && std::isspace(static_cast<unsigned char>(serial[last - 1])))
            --last;
        serial = serial.substr(first, last - first);
        return serial.empty() ? std::optional<std::string>() : serial;
    }

    namespace
    {
        std::string trim(const std::string &value)
        {
            std::size_t begin = 0;
            std::size_t end = value.size();
            while (begin < end && std::isspace(static_cast<unsigned char>(value[begin])))
                ++begin;
            while (end > begin && std::isspace(static_cast<unsigned char>(value[end - 1])))
                --end;
            return value.substr(begin, end - begin);
        }

        std::string toLower(std::string value)
        {
            std::transform(value.begin(), value.end(), value.begin(),
                           [](unsigned char c)
                           { return static_cast<char>(std::tolower(c)); });
            return value;
        }

        [[maybe_unused]] std::string firstMatch(const std::string &pattern, const std::string &text)
        {
            std::smatch match;
            if (std::regex_search(text, match, std::regex(pattern)))
                return match[1].str();
            return "";
        }

        [[maybe_unused]] std::vector<std::string> allMatches(const std::string &pattern, const std::string &text)
        {
            std::vector<std::string> out;
            const std::regex expression(pattern);
            for (auto it = std::sregex_iterator(text.begin(), text.end(), expression);
                 it != std::sregex_iterator(); ++it)
                out.push_back((*it)[1].str());
            return out;
        }

        [[maybe_unused]] std::string multiInstance(std::vector<std::string> values)
        {
            for (auto &value : values)
                value = trim(value);
            values.erase(std::remove_if(values.begin(), values.end(),
                                        [](const std::string &v)
                                        { return v.empty(); }),
                         values.end());
            std::sort(values.begin(), values.end());
            std::string joined;
            for (const auto &value : values)
            {
                if (!joined.empty())
                    joined += "|";
                joined += value;
            }
            return joined;
        }

        std::optional<std::string> readFileTrimmed(const std::string &path)
        {
            std::ifstream file(path);
            if (!file)
                return std::nullopt;
            std::string content((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
            const std::string trimmed = trim(content);
            return trimmed.empty() ? std::optional<std::string>() : trimmed;
        }

#if defined(_WIN32)
        std::string popenCapture(const std::string &command, unsigned long timeoutMs = 4000)
        {
            std::string output;
            const auto appendBounded = [&output](const char *data, std::size_t length)
            {
                constexpr std::size_t limit = 1024 * 1024;
                const std::size_t remaining = output.size() < limit ? limit - output.size() : 0;
                output.append(data, length < remaining ? length : remaining);
            };
            SECURITY_ATTRIBUTES security{sizeof(SECURITY_ATTRIBUTES), nullptr, TRUE};
            HANDLE readPipe = nullptr;
            HANDLE writePipe = nullptr;
            if (!CreatePipe(&readPipe, &writePipe, &security, 0) ||
                !SetHandleInformation(readPipe, HANDLE_FLAG_INHERIT, 0))
            {
                if (readPipe != nullptr)
                    CloseHandle(readPipe);
                if (writePipe != nullptr)
                    CloseHandle(writePipe);
                return "";
            }

            STARTUPINFOA startup{};
            startup.cb = sizeof(startup);
            startup.dwFlags = STARTF_USESTDHANDLES;
            startup.hStdInput = GetStdHandle(STD_INPUT_HANDLE);
            startup.hStdOutput = writePipe;
            startup.hStdError = writePipe;
            PROCESS_INFORMATION process{};
            std::string commandLine = "cmd.exe /d /s /c " + command;
            std::vector<char> mutableCommand(commandLine.begin(), commandLine.end());
            mutableCommand.push_back('\0');
            const bool started = CreateProcessA(nullptr, mutableCommand.data(), nullptr, nullptr, TRUE,
                                                CREATE_NO_WINDOW, nullptr, nullptr, &startup, &process) != FALSE;
            CloseHandle(writePipe);
            if (!started)
            {
                CloseHandle(readPipe);
                return "";
            }

            HANDLE job = CreateJobObjectA(nullptr, nullptr);
            if (job != nullptr)
            {
                JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits{};
                limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
                if (!SetInformationJobObject(job, JobObjectExtendedLimitInformation, &limits, sizeof(limits)) ||
                    !AssignProcessToJobObject(job, process.hProcess))
                {
                    CloseHandle(job);
                    job = nullptr;
                }
            }

            const auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(timeoutMs);
            bool finished = false;
            while (!finished)
            {
                DWORD available = 0;
                while (PeekNamedPipe(readPipe, nullptr, 0, nullptr, &available, nullptr) && available > 0)
                {
                    char buffer[4096];
                    DWORD read = 0;
                    const DWORD wanted = std::min<DWORD>(available, sizeof(buffer));
                    if (!ReadFile(readPipe, buffer, wanted, &read, nullptr) || read == 0)
                        break;
                    appendBounded(buffer, read);
                    available -= read;
                }
                if (WaitForSingleObject(process.hProcess, 0) == WAIT_OBJECT_0)
                {
                    finished = true;
                    continue;
                }
                if (std::chrono::steady_clock::now() >= deadline)
                {
                    if (job != nullptr)
                        TerminateJobObject(job, 1);
                    else
                        TerminateProcess(process.hProcess, 1);
                    WaitForSingleObject(process.hProcess, 1000);
                    finished = true;
                    continue;
                }
                std::this_thread::sleep_for(std::chrono::milliseconds(10));
            }

            DWORD available = 0;
            while (PeekNamedPipe(readPipe, nullptr, 0, nullptr, &available, nullptr) && available > 0)
            {
                char buffer[4096];
                DWORD read = 0;
                const DWORD wanted = std::min<DWORD>(available, sizeof(buffer));
                if (!ReadFile(readPipe, buffer, wanted, &read, nullptr) || read == 0)
                    break;
                appendBounded(buffer, read);
                available -= read;
            }
            CloseHandle(readPipe);
            CloseHandle(process.hThread);
            CloseHandle(process.hProcess);
            if (job != nullptr)
                CloseHandle(job);
            return output;
        }

        void mkdirForPath(const std::string &directory)
        {
            CreateDirectoryA(directory.c_str(), nullptr);
        }
#else
        std::string popenCapture(const std::string &command, unsigned long timeoutMs = 4000)
        {
            std::string output;
            constexpr std::size_t maxOutput = 1024 * 1024;
            int descriptors[2]{};
            if (::pipe(descriptors) != 0)
                return "";

            const pid_t child = ::fork();
            if (child < 0)
            {
                ::close(descriptors[0]);
                ::close(descriptors[1]);
                return "";
            }
            if (child == 0)
            {
                // A process group lets timeout cleanup include grandchildren
                // spawned by system_profiler, dmidecode, or a shell pipeline.
                ::setpgid(0, 0);
                ::close(descriptors[0]);
                ::dup2(descriptors[1], STDOUT_FILENO);
                ::dup2(descriptors[1], STDERR_FILENO);
                ::close(descriptors[1]);
                ::execl("/bin/sh", "sh", "-c", command.c_str(), static_cast<char *>(nullptr));
                ::_exit(127);
            }

            ::close(descriptors[1]);
            ::setpgid(child, child); // harmless if the child won the race
            const int flags = ::fcntl(descriptors[0], F_GETFL, 0);
            if (flags >= 0)
                ::fcntl(descriptors[0], F_SETFL, flags | O_NONBLOCK);

            const auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(timeoutMs);
            bool exited = false;
            bool eof = false;
            bool timedOut = false;
            while (!eof && !timedOut)
            {
                char buffer[4096];
                for (;;)
                {
                    const ssize_t count = ::read(descriptors[0], buffer, sizeof(buffer));
                    if (count > 0)
                    {
                        const std::size_t remaining = output.size() < maxOutput ? maxOutput - output.size() : 0;
                        output.append(buffer, std::min<std::size_t>(static_cast<std::size_t>(count), remaining));
                        continue;
                    }
                    if (count == 0)
                        eof = true;
                    break;
                }

                if (!exited)
                {
                    int status = 0;
                    const pid_t result = ::waitpid(child, &status, WNOHANG);
                    exited = result == child;
                }
                if (exited && eof)
                    break;
                if (std::chrono::steady_clock::now() >= deadline)
                {
                    timedOut = true;
                    break;
                }

                struct pollfd waitForOutput
                {
                    descriptors[0], POLLIN | POLLHUP, 0
                };
                ::poll(&waitForOutput, 1, 10);
            }

            if (timedOut)
            {
                ::kill(-child, SIGKILL);
                ::kill(child, SIGKILL);
            }
            if (!exited)
            {
                int status = 0;
                while (::waitpid(child, &status, 0) < 0 && errno == EINTR)
                {
                }
            }
            ::close(descriptors[0]);
            return output;
        }

        void mkdirForPath(const std::string &directory)
        {
            std::string partial;
            std::istringstream segments(directory);
            std::string segment;
            while (std::getline(segments, segment, '/'))
            {
                if (segment.empty())
                {
                    partial = "/";
                    continue;
                }
                if (!partial.empty() && partial.back() != '/')
                    partial += "/";
                partial += segment;
                ::mkdir(partial.c_str(), 0700);
            }
        }
#endif

        // Directory-backed store (every platform, used for the storePath
        // override and as the non-Windows default).
        class DirStore final : public Store
        {
        public:
            bool open(const std::string &directory, std::string &error)
            {
                directory_ = directory;
                mkdirForPath(directory);
#if defined(_WIN32)
                const DWORD attributes = GetFileAttributesA(directory.c_str());
                if (attributes == INVALID_FILE_ATTRIBUTES || (attributes & FILE_ATTRIBUTE_DIRECTORY) == 0)
                {
                    error = "slhwid: store directory unavailable: " + directory;
                    return false;
                }
#else
                struct stat info
                {
                };
                if (stat(directory.c_str(), &info) != 0 || !S_ISDIR(info.st_mode))
                {
                    error = "slhwid: store directory unavailable: " + directory;
                    return false;
                }
                if (::chmod(directory.c_str(), 0700) != 0)
                {
                    error = "slhwid: cannot secure store directory: " + directory;
                    return false;
                }
#endif
                return true;
            }

            std::string lockDirectory() const override { return directory_; }

            Read read(const std::string &key) override
            {
                Read result;
                std::ifstream file(pathFor(key), std::ios::binary);
                if (!file)
                    return result; // absent
                result.data = std::vector<unsigned char>((std::istreambuf_iterator<char>(file)),
                                                         std::istreambuf_iterator<char>());
                return result;
            }

            bool write(const std::string &key, const std::vector<unsigned char> &data, std::string &error) override
            {
                std::string path = pathFor(key);
                const std::string temporary = path + ".tmp-" + std::to_string(
#if defined(_WIN32)
                                                  GetCurrentProcessId()
#else
                                                  getpid()
#endif
                                                  ) + "-" + std::to_string(
                                                  std::chrono::high_resolution_clock::now().time_since_epoch().count());
                {
                    std::ofstream file(temporary, std::ios::binary | std::ios::trunc);
                    if (!file)
                    {
                        error = "slhwid: cannot write " + temporary;
                        return false;
                    }
                    file.write(reinterpret_cast<const char *>(data.data()), static_cast<std::streamsize>(data.size()));
                    file.flush();
                    if (!file)
                    {
                        std::remove(temporary.c_str());
                        error = "slhwid: cannot write " + temporary;
                        return false;
                    }
                }
#if defined(_WIN32)
                if (!MoveFileExA(temporary.c_str(), path.c_str(), MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH))
                {
                    std::remove(temporary.c_str());
                    error = "slhwid: cannot replace " + path;
                    return false;
                }
#else
                if (::rename(temporary.c_str(), path.c_str()) != 0)
                {
                    std::remove(temporary.c_str());
                    error = "slhwid: cannot replace " + path;
                    return false;
                }
#endif
#if !defined(_WIN32)
                if (::chmod(path.c_str(), 0600) != 0)
                {
                    error = "slhwid: cannot secure " + path;
                    return false;
                }
#endif
                return true;
            }

        private:
            std::string directory_;

            std::string pathFor(const std::string &key) const
            {
                if (key == "slstore")
                    return directory_ + "/slstore.bin";
                // key is "HWID-<hex16>"
                std::string name = toLower(key);
                name.erase(0, strlen("HWID-"));
                return directory_ + "/hwid-" + name + ".bin";
            }
        };
    }


    // ── CSPRNG (platform) ──────────────────────────────────────────────

#if defined(_WIN32)
    bool randomBytes(unsigned char *out, std::size_t n)
    {
        return BCryptGenRandom(nullptr, out, static_cast<unsigned long>(n),
                               BCRYPT_USE_SYSTEM_PREFERRED_RNG) == 0;
    }
#elif defined(__APPLE__)
    bool randomBytes(unsigned char *out, std::size_t n)
    {
        arc4random_buf(out, n);
        return true;
    }
#elif defined(__linux__)
    bool randomBytes(unsigned char *out, std::size_t n)
    {
        std::size_t done = 0;
        while (done < n)
        {
            const ssize_t got = ::getrandom(out + done, n - done, 0);
            if (got < 0)
                return false;
            done += static_cast<std::size_t>(got);
        }
        return true;
    }
#else
    bool randomBytes(unsigned char *out, std::size_t n)
    {
        std::ifstream urandom("/dev/urandom", std::ios::binary);
        return urandom && urandom.read(reinterpret_cast<char *>(out),
                                       static_cast<std::streamsize>(n)).good();
    }
#endif

    // ── storage defaults ───────────────────────────────────────────────

#if defined(_WIN32)

    namespace
    {
        std::string localLockDirectory()
        {
            char buffer[MAX_PATH + 1] = {};
            const DWORD length = GetEnvironmentVariableA("LOCALAPPDATA", buffer, MAX_PATH);
            if (length > 0 && length < MAX_PATH)
                return std::string(buffer, length) + "\\SystemLocker";
            const char *profile = std::getenv("USERPROFILE");
            return std::string(profile != nullptr ? profile : ".") + "\\AppData\\Local\\SystemLocker";
        }

        class RegistryStore final : public Store
        {
        public:
            Read read(const std::string &key) override
            {
                selectRoot();
                return selectedRoot_ ? readFrom(*selectedRoot_, key) : Read{};
            }

            bool write(const std::string &key, const std::vector<unsigned char> &data, std::string &error) override
            {
                if (selectedRoot_)
                {
                    if (writeTo(*selectedRoot_, key, data))
                        return true;
                    error = "slhwid: registry write failed";
                    return false;
                }
                for (const HKEY root : {HKEY_LOCAL_MACHINE, HKEY_CURRENT_USER})
                {
                    if (writeTo(root, key, data))
                    {
                        selectedRoot_ = root;
                        return true;
                    }
                }
                error = "slhwid: registry write failed";
                return false;
            }

            std::string lockDirectory() const override { return localLockDirectory(); }

        private:
            std::optional<HKEY> selectedRoot_;

            static Read readFrom(HKEY root, const std::string &key)
            {
                Read result;
                HKEY handle;
                if (RegOpenKeyExA(root, "SOFTWARE\\SystemLocker", 0,
                                  KEY_READ | KEY_WOW64_64KEY, &handle) != ERROR_SUCCESS)
                    return result;
                DWORD type = 0;
                DWORD size = 0;
                if (RegQueryValueExA(handle, key.c_str(), nullptr, &type, nullptr, &size) != ERROR_SUCCESS ||
                    type != REG_BINARY)
                {
                    RegCloseKey(handle);
                    return result;
                }
                std::vector<unsigned char> data(size);
                if (RegQueryValueExA(handle, key.c_str(), nullptr, nullptr, data.data(), &size) == ERROR_SUCCESS)
                {
                    data.resize(size);
                    result.data = std::move(data);
                }
                RegCloseKey(handle);
                return result;
            }

            static bool writeTo(HKEY root, const std::string &key, const std::vector<unsigned char> &data)
            {
                HKEY handle;
                if (RegCreateKeyExA(root, "SOFTWARE\\SystemLocker", 0, nullptr, REG_OPTION_NON_VOLATILE,
                                    KEY_SET_VALUE | KEY_WOW64_64KEY, nullptr, &handle, nullptr) != ERROR_SUCCESS)
                    return false;
                const LSTATUS status = RegSetValueExA(handle, key.c_str(), 0, REG_BINARY,
                                                      data.data(), static_cast<DWORD>(data.size()));
                RegCloseKey(handle);
                return status == ERROR_SUCCESS;
            }

            void selectRoot()
            {
                if (selectedRoot_)
                    return;
                const bool machineHelper = readFrom(HKEY_LOCAL_MACHINE, "HWID-device").data.has_value();
                const bool machineSlstore = readFrom(HKEY_LOCAL_MACHINE, "slstore").data.has_value();
                const bool userHelper = readFrom(HKEY_CURRENT_USER, "HWID-device").data.has_value();
                const bool userSlstore = readFrom(HKEY_CURRENT_USER, "slstore").data.has_value();
                // Prefer a complete generation, then the helper's root. An
                // incomplete helper must fail closed instead of borrowing a
                // mandatory secret from the other hive.
                switch (selectRegistryRoot(machineHelper, machineSlstore, userHelper, userSlstore))
                {
                case RegistryRootSelection::machine:
                    selectedRoot_ = HKEY_LOCAL_MACHINE;
                    break;
                case RegistryRootSelection::user:
                    selectedRoot_ = HKEY_CURRENT_USER;
                    break;
                case RegistryRootSelection::none:
                    break;
                }
            }
        };
    }

    std::shared_ptr<Store> defaultStore(const std::string &overridePath, std::string &error)
    {
        if (!overridePath.empty())
        {
            auto store = std::make_shared<DirStore>();
            if (!store->open(overridePath, error))
                return nullptr;
            return store;
        }
        return std::make_shared<RegistryStore>();
    }

#else // POSIX

    std::shared_ptr<Store> defaultStore(const std::string &overridePath, std::string &error)
    {
        std::string directory = overridePath;
        if (directory.empty())
        {
            const char *home = std::getenv("HOME");
            const std::string homeDir = home != nullptr ? home : ".";
#if defined(__APPLE__)
            directory = homeDir + "/Library/Application Support/SystemLocker";
#else
            const char *xdg = std::getenv("XDG_DATA_HOME");
            directory = (xdg != nullptr && *xdg != 0 ? std::string(xdg) : homeDir + "/.local/share") + "/systemlocker";
#endif
        }
        auto store = std::make_shared<DirStore>();
        if (!store->open(directory, error))
            return nullptr;
        return store;
    }

#endif

    bool acquireStorageLock(const std::string &directory, std::function<void()> &release, std::string &error)
    {
        if (directory.empty())
            return true;
        mkdirForPath(directory);
        const std::string path = directory + (directory.back() == '/' || directory.back() == '\\' ? "" : "/") + ".slhwid.lock";
        std::vector<unsigned char> token(16);
        if (!randomBytes(token.data(), token.size()))
        {
            error = "slhwid: cannot create storage lock token";
            return false;
        }
        const std::string contents = "SLHwidLockV1\n" + std::to_string(
#if defined(_WIN32)
                                         GetCurrentProcessId()
#else
                                         getpid()
#endif
                                         ) + "\n" + toLowerHex(token) + "\n";
        secureWipe(token.data(), token.size());
        const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(30);
        const auto stale = [&path]()
        {
            std::ifstream current(path, std::ios::binary);
            std::string header;
            std::string processText;
            std::getline(current, header);
            std::getline(current, processText);
            if (header == "SLHwidLockV1")
            {
                try
                {
                    const auto processId = static_cast<unsigned long>(std::stoul(processText));
#if defined(_WIN32)
                    HANDLE process = OpenProcess(SYNCHRONIZE, FALSE, static_cast<DWORD>(processId));
                    if (process == nullptr)
                        return GetLastError() != ERROR_ACCESS_DENIED;
                    DWORD exitCode = 0;
                    const bool dead = !GetExitCodeProcess(process, &exitCode) || exitCode != STILL_ACTIVE;
                    CloseHandle(process);
                    return dead;
#else
                    if (::kill(static_cast<pid_t>(processId), 0) == 0 || errno == EPERM)
                        return false;
                    if (errno == ESRCH)
                        return true;
#endif
                }
                catch (const std::exception &)
                {
                    // Fall through to conservative age-based recovery.
                }
            }
#if defined(_WIN32)
            WIN32_FILE_ATTRIBUTE_DATA attributes{};
            if (!GetFileAttributesExA(path.c_str(), GetFileExInfoStandard, &attributes))
                return false;
            ULARGE_INTEGER modified{};
            modified.LowPart = attributes.ftLastWriteTime.dwLowDateTime;
            modified.HighPart = attributes.ftLastWriteTime.dwHighDateTime;
            FILETIME nowFileTime{};
            GetSystemTimeAsFileTime(&nowFileTime);
            ULARGE_INTEGER now{};
            now.LowPart = nowFileTime.dwLowDateTime;
            now.HighPart = nowFileTime.dwHighDateTime;
            return now.QuadPart > modified.QuadPart + 120ULL * 10000000ULL;
#else
            struct stat info {};
            return ::stat(path.c_str(), &info) == 0 && std::time(nullptr) - info.st_mtime >= 120;
#endif
        };

        for (;;)
        {
#if defined(_WIN32)
            HANDLE handle = CreateFileA(path.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, nullptr);
            if (handle != INVALID_HANDLE_VALUE)
            {
                DWORD written = 0;
                const bool ok = WriteFile(handle, contents.data(), static_cast<DWORD>(contents.size()), &written, nullptr) &&
                                written == contents.size();
                CloseHandle(handle);
                if (!ok)
                {
                    DeleteFileA(path.c_str());
                    error = "slhwid: cannot write storage lock";
                    return false;
                }
                release = [path, contents]
                {
                    std::string value;
                    {
                        std::ifstream current(path, std::ios::binary);
                        value.assign(std::istreambuf_iterator<char>(current), std::istreambuf_iterator<char>());
                    }
                    if (value == contents)
                        DeleteFileA(path.c_str());
                };
                return true;
            }
            if (GetLastError() != ERROR_FILE_EXISTS)
            {
                error = "slhwid: cannot acquire storage lock";
                return false;
            }
            if (stale())
                DeleteFileA(path.c_str());
#else
            const int handle = ::open(path.c_str(), O_WRONLY | O_CREAT | O_EXCL, 0600);
            if (handle >= 0)
            {
                const ssize_t written = ::write(handle, contents.data(), contents.size());
                ::close(handle);
                if (written != static_cast<ssize_t>(contents.size()))
                {
                    ::unlink(path.c_str());
                    error = "slhwid: cannot write storage lock";
                    return false;
                }
                release = [path, contents]
                {
                    std::string value;
                    {
                        std::ifstream current(path, std::ios::binary);
                        value.assign(std::istreambuf_iterator<char>(current), std::istreambuf_iterator<char>());
                    }
                    if (value == contents)
                        ::unlink(path.c_str());
                };
                return true;
            }
            if (errno != EEXIST)
            {
                error = "slhwid: cannot acquire storage lock";
                return false;
            }
            if (stale())
                ::unlink(path.c_str());
#endif
            if (std::chrono::steady_clock::now() >= deadline)
            {
                error = "slhwid: storage is busy; retry the operation";
                return false;
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(50));
        }
    }

    // ── collectors ─────────────────────────────────────────────────────

#if defined(_WIN32)

    namespace
    {
        std::wstring utf8ToWide(const std::string &value)
        {
            if (value.empty())
                return {};
            const int length = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, value.data(),
                                                   static_cast<int>(value.size()), nullptr, 0);
            if (length <= 0)
                return {};
            std::wstring wide(static_cast<std::size_t>(length), L'\0');
            MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, value.data(),
                                static_cast<int>(value.size()), wide.data(), length);
            return wide;
        }

        std::string wideToUtf8(const std::wstring &value)
        {
            if (value.empty())
                return {};
            const int length = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, value.data(),
                                                   static_cast<int>(value.size()), nullptr, 0, nullptr, nullptr);
            if (length <= 0)
                return {};
            std::string utf8(static_cast<std::size_t>(length), '\0');
            WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, value.data(),
                                static_cast<int>(value.size()), utf8.data(), length, nullptr, nullptr);
            return utf8;
        }

        std::optional<std::string> registryValue(const std::string &path, const std::string &name)
        {
            const std::wstring widePath = utf8ToWide(path);
            const std::wstring wideName = utf8ToWide(name);
            HKEY handle;
            if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, widePath.c_str(), 0,
                              KEY_READ | KEY_WOW64_64KEY, &handle) != ERROR_SUCCESS)
                return std::nullopt;
            DWORD type = 0;
            DWORD size = 0;
            if (RegQueryValueExW(handle, wideName.c_str(), nullptr, &type, nullptr, &size) != ERROR_SUCCESS)
            {
                RegCloseKey(handle);
                return std::nullopt;
            }
            std::string value;
            if (type == REG_SZ || type == REG_EXPAND_SZ)
            {
                std::vector<wchar_t> buffer(size / sizeof(wchar_t) + 1, L'\0');
                if (RegQueryValueExW(handle, wideName.c_str(), nullptr, nullptr,
                                     reinterpret_cast<LPBYTE>(buffer.data()), &size) != ERROR_SUCCESS)
                {
                    RegCloseKey(handle);
                    return std::nullopt;
                }
                value = wideToUtf8(std::wstring(buffer.data()));
            }
            else if (type == REG_MULTI_SZ)
            {
                std::vector<wchar_t> buffer(size / sizeof(wchar_t) + 2, L'\0');
                if (RegQueryValueExW(handle, wideName.c_str(), nullptr, nullptr,
                                     reinterpret_cast<LPBYTE>(buffer.data()), &size) != ERROR_SUCCESS)
                {
                    RegCloseKey(handle);
                    return std::nullopt;
                }
                std::wstring joined;
                const std::size_t chars = size / sizeof(wchar_t);
                for (std::size_t i = 0; i < chars && buffer[i] != 0;)
                {
                    const std::wstring part(buffer.data() + i);
                    if (!joined.empty())
                        joined += L" ";
                    joined += part;
                    i += part.size() + 1;
                }
                value = wideToUtf8(joined);
            }
            else if (type == REG_DWORD)
            {
                DWORD number = 0;
                DWORD dwordSize = sizeof(number);
                if (RegQueryValueExW(handle, wideName.c_str(), nullptr, nullptr,
                                     reinterpret_cast<LPBYTE>(&number), &dwordSize) != ERROR_SUCCESS)
                {
                    RegCloseKey(handle);
                    return std::nullopt;
                }
                value = std::to_string(number);
            }
            else
            {
                RegCloseKey(handle);
                return std::nullopt;
            }
            RegCloseKey(handle);
            return value;
        }

        std::vector<std::string> registrySubkeyNames(const std::string &path)
        {
            std::vector<std::string> names;
            const std::wstring widePath = utf8ToWide(path);
            HKEY handle;
            if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, widePath.c_str(), 0,
                              KEY_READ | KEY_WOW64_64KEY, &handle) != ERROR_SUCCESS)
                return names;
            wchar_t name[256];
            for (DWORD index = 0;; ++index)
            {
                DWORD nameSize = static_cast<DWORD>(std::size(name));
                if (RegEnumKeyExW(handle, index, name, &nameSize, nullptr, nullptr, nullptr, nullptr) != ERROR_SUCCESS)
                    break;
                names.push_back(wideToUtf8(std::wstring(name, nameSize)));
            }
            RegCloseKey(handle);
            std::sort(names.begin(), names.end());
            return names;
        }

        std::optional<std::vector<unsigned char>> registryBinary(const std::string &path, const std::string &name)
        {
            const std::wstring widePath = utf8ToWide(path);
            const std::wstring wideName = utf8ToWide(name);
            HKEY handle;
            if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, widePath.c_str(), 0,
                              KEY_READ | KEY_WOW64_64KEY, &handle) != ERROR_SUCCESS)
                return std::nullopt;
            DWORD type = 0;
            DWORD size = 0;
            if (RegQueryValueExW(handle, wideName.c_str(), nullptr, &type, nullptr, &size) != ERROR_SUCCESS ||
                type != REG_BINARY)
            {
                RegCloseKey(handle);
                return std::nullopt;
            }
            std::vector<unsigned char> data(size);
            if (RegQueryValueExW(handle, wideName.c_str(), nullptr, nullptr, data.data(), &size) != ERROR_SUCCESS)
                data.clear();
            else
                data.resize(size);
            RegCloseKey(handle);
            return data;
        }

        std::optional<std::string> systemUuid()
        {
            constexpr DWORD provider = 0x52534D42; // 'RSMB'
            const UINT size = GetSystemFirmwareTable(provider, 0, nullptr, 0);
            if (size < 8 || size > 1024 * 1024)
                return std::nullopt;
            std::vector<unsigned char> raw(size);
            if (GetSystemFirmwareTable(provider, 0, raw.data(), size) != size)
                return std::nullopt;
            return parseRawSmbiosUuid(raw);
        }

        std::vector<std::string> physicalDiskSerials()
        {
            std::vector<std::string> serials;
            STORAGE_PROPERTY_QUERY query{};
            query.PropertyId = StorageDeviceProperty;
            query.QueryType = PropertyStandardQuery;
            for (int index = 0; index < 32; ++index)
            {
                const std::string path = "\\\\.\\PhysicalDrive" + std::to_string(index);
                HANDLE disk = CreateFileA(path.c_str(), 0, FILE_SHARE_READ | FILE_SHARE_WRITE,
                                          nullptr, OPEN_EXISTING, 0, nullptr);
                if (disk == INVALID_HANDLE_VALUE)
                    continue;

                STORAGE_DESCRIPTOR_HEADER header{};
                DWORD returned = 0;
                if (!DeviceIoControl(disk, IOCTL_STORAGE_QUERY_PROPERTY, &query, sizeof(query),
                                     &header, sizeof(header), &returned, nullptr) ||
                    header.Size < sizeof(STORAGE_DEVICE_DESCRIPTOR) || header.Size > 1024 * 1024)
                {
                    CloseHandle(disk);
                    continue;
                }

                std::vector<unsigned char> buffer(header.Size);
                if (!DeviceIoControl(disk, IOCTL_STORAGE_QUERY_PROPERTY, &query, sizeof(query),
                                     buffer.data(), static_cast<DWORD>(buffer.size()), &returned, nullptr) ||
                    returned < sizeof(STORAGE_DEVICE_DESCRIPTOR))
                {
                    CloseHandle(disk);
                    continue;
                }
                CloseHandle(disk);

                if (const auto serial = parseStorageDescriptorSerial(buffer, returned))
                    serials.push_back(*serial);
            }
            return serials;
        }

        std::optional<std::string> volumeSerial()
        {
            const char *drive = std::getenv("SystemDrive");
            std::string root = drive != nullptr ? drive : "C:";
            if (root.empty() || (root.back() != '\\' && root.back() != '/'))
                root += "\\";
            DWORD serial = 0;
            if (!GetVolumeInformationA(root.c_str(), nullptr, 0, &serial, nullptr, nullptr, nullptr, 0))
                return std::nullopt;
            char formatted[10] = {};
            std::snprintf(formatted, sizeof(formatted), "%04lX-%04lX",
                          static_cast<unsigned long>(serial >> 16),
                          static_cast<unsigned long>(serial & 0xffff));
            return std::string(formatted);
        }

        std::optional<std::string> physicalMac()
        {
            ULONG size = 15 * 1024;
            std::vector<unsigned char> buffer(size);
            ULONG status = GetAdaptersAddresses(
                AF_UNSPEC,
                GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER,
                nullptr, reinterpret_cast<IP_ADAPTER_ADDRESSES *>(buffer.data()), &size);
            if (status == ERROR_BUFFER_OVERFLOW)
            {
                buffer.resize(size);
                status = GetAdaptersAddresses(
                    AF_UNSPEC,
                    GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER,
                    nullptr, reinterpret_cast<IP_ADAPTER_ADDRESSES *>(buffer.data()), &size);
            }
            if (status != ERROR_SUCCESS)
                return std::nullopt;

            const std::vector<std::string> virtualMarkers{
                "vethernet", "vmware", "virtual", "loopback", "tap", "tun", "zerotier",
                "wsl", "docker", "bluetooth", "tailscale", "vpn"};
            for (auto *adapter = reinterpret_cast<IP_ADAPTER_ADDRESSES *>(buffer.data());
                 adapter != nullptr; adapter = adapter->Next)
            {
                if (adapter->IfType == IF_TYPE_SOFTWARE_LOOPBACK || adapter->IfType == IF_TYPE_TUNNEL ||
                    adapter->PhysicalAddressLength != 6)
                    continue;
                std::string label = adapter->AdapterName != nullptr ? adapter->AdapterName : "";
                if (adapter->FriendlyName != nullptr)
                {
                    const int bytes = WideCharToMultiByte(CP_UTF8, 0, adapter->FriendlyName, -1,
                                                         nullptr, 0, nullptr, nullptr);
                    if (bytes > 1)
                    {
                        std::string friendly(static_cast<std::size_t>(bytes), '\0');
                        WideCharToMultiByte(CP_UTF8, 0, adapter->FriendlyName, -1,
                                            friendly.data(), bytes, nullptr, nullptr);
                        friendly.pop_back();
                        label += " " + friendly;
                    }
                }
                label = toLower(label);
                if (std::any_of(virtualMarkers.begin(), virtualMarkers.end(), [&label](const std::string &marker)
                                { return label.find(marker) != std::string::npos; }))
                    continue;

                static constexpr char hex[] = "0123456789ABCDEF";
                std::string encoded;
                encoded.reserve(12);
                for (ULONG i = 0; i < adapter->PhysicalAddressLength; ++i)
                {
                    const unsigned char byte = adapter->PhysicalAddress[i];
                    encoded.push_back(hex[byte >> 4]);
                    encoded.push_back(hex[byte & 0x0f]);
                }
                return encoded;
            }
            return std::nullopt;
        }

        void put(std::map<std::string, std::string> &factors, const std::string &slot, const std::optional<std::string> &value)
        {
            if (value && !value->empty())
                factors[slot] = *value;
        }

        std::map<std::string, std::string> windowsSchemaV2Factors()
        {
            // Use one bounded CIM query for enrichment. Native sources remain
            // authoritative, and explicit UTF-8 keeps non-ASCII values stable.
            const std::string script =
                "[Console]::OutputEncoding=[Text.UTF8Encoding]::new($false);$OutputEncoding=[Console]::OutputEncoding;$ErrorActionPreference='SilentlyContinue';"
                "function Emit($n,$v){$c=@($v|?{$_ -ne $null -and ([string]$_).Trim().Length -gt 0}|%{([string]$_).Trim()}|sort);if($c.Count -gt 0){Write-Output ($n+'='+($c -join '|'))}};"
                "$p=Get-CimInstance Win32_ComputerSystemProduct;Emit 'system_uuid' $p.UUID;Emit 'system_serial' $p.IdentifyingNumber;"
                "Emit 'chassis_serial' (Get-CimInstance Win32_SystemEnclosure).SerialNumber;"
                "Emit 'disk_serial' (Get-CimInstance Win32_DiskDrive).SerialNumber;"
                "Emit 'memory_modules' (Get-CimInstance Win32_PhysicalMemory).SerialNumber;"
                "Emit 'nic_identity' (Get-CimInstance Win32_NetworkAdapter|?{$_.PhysicalAdapter}).PermanentAddress;"
                "Emit 'battery_serial' (Get-CimInstance -Namespace root/wmi -ClassName BatteryStaticData).SerialNumber;"
                "$ek=Get-TpmEndorsementKeyInfo -HashAlgorithm Sha256;if($ek.IsPresent){Emit 'tpm_ek' $ek.PublicKeyHash}";
            const auto output = popenCapture(
                "powershell.exe -NoProfile -NonInteractive -Command \"" + script + "\" 2>nul", 6000);
            std::map<std::string, std::string> factors;
            std::istringstream lines(output);
            std::string line;
            while (std::getline(lines, line))
            {
                line = trim(line);
                const auto separator = line.find('=');
                if (separator != std::string::npos && separator > 0 && separator + 1 < line.size())
                    factors[line.substr(0, separator)] = line.substr(separator + 1);
            }
            return factors;
        }
    }

    std::map<std::string, std::string> collectFactors(std::string &error)
    {
        (void)error; // Individual collector failures are represented as absent slots.
        std::map<std::string, std::string> factors;
        const std::string bios = "HARDWARE\\DESCRIPTION\\System\\BIOS";

        put(factors, "machine_guid", registryValue("SOFTWARE\\Microsoft\\Cryptography", "MachineGuid"));
        if (const auto hardwareId = registryValue("SYSTEM\\CurrentControlSet\\Control\\SystemInformation", "ComputerHardwareId"))
        {
            std::string trimmed = *hardwareId;
            trimmed.erase(std::remove(trimmed.begin(), trimmed.end(), '{'), trimmed.end());
            trimmed.erase(std::remove(trimmed.begin(), trimmed.end(), '}'), trimmed.end());
            put(factors, "product_uuid", trimmed);
        }
        // ComputerHardwareId is not the SMBIOS UUID exposed by CIM. Read the
        // UUID directly so PowerShell availability cannot change this slot.
        put(factors, "system_uuid", systemUuid());
        put(factors, "board_serial", registryValue(bios, "BaseBoardSerialNumber"));
        put(factors, "cpu_id", registryValue("HARDWARE\\DESCRIPTION\\System\\CentralProcessor\\0", "Identifier"));

        std::vector<std::string> firmwareParts;
        if (const auto systemBios = registryValue(bios, "SystemBiosVersion"))
            firmwareParts.push_back(*systemBios);
        if (const auto biosVersion = registryValue(bios, "BIOSVersion"))
            firmwareParts.push_back(*biosVersion);
        put(factors, "firmware", multiInstance(firmwareParts));

        const auto build = registryValue("SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", "CurrentBuildNumber");
        const auto ubr = registryValue("SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", "UBR");
        if (build && ubr)
            factors["os_build"] = *build + "-" + *ubr;

        wchar_t computerName[32768]{};
        const DWORD computerNameLength = GetEnvironmentVariableW(
            L"COMPUTERNAME", computerName, static_cast<DWORD>(std::size(computerName)));
        if (computerNameLength > 0 && computerNameLength < std::size(computerName))
            factors["computer_name"] = wideToUtf8(std::wstring(computerName, computerNameLength));

        std::vector<std::string> gpuDescriptions;
        const std::string displayClass = "SYSTEM\\CurrentControlSet\\Control\\Class\\{4d36e968-e325-11ce-bfc1-08002be10318}";
        for (const auto &subkey : registrySubkeyNames(displayClass))
            if (const auto description = registryValue(displayClass + "\\" + subkey, "DriverDesc"))
                gpuDescriptions.push_back(*description);
        put(factors, "gpu_id", multiInstance(gpuDescriptions));

        std::vector<std::string> edidBlobs;
        const std::string displayPath = "SYSTEM\\CurrentControlSet\\Enum\\DISPLAY";
        for (const auto &adapter : registrySubkeyNames(displayPath))
        {
            const std::string adapterPath = displayPath + "\\" + adapter;
            for (const auto &instance : registrySubkeyNames(adapterPath))
            {
                if (const auto blob = registryBinary(
                        adapterPath + "\\" + instance + "\\Device Parameters", "EDID");
                    blob && !blob->empty())
                    edidBlobs.push_back(toLowerHex(*blob));
            }
        }
        put(factors, "monitor_edid", multiInstance(edidBlobs));

        put(factors, "disk_serial", multiInstance(physicalDiskSerials()));

        {
            MEMORYSTATUSEX status{};
            status.dwLength = sizeof(status);
            if (GlobalMemoryStatusEx(&status))
                factors["ram_total"] = std::to_string(status.ullTotalPhys);
        }

        put(factors, "volume_id", volumeSerial());
        put(factors, "mac", physicalMac());

        // Schema-v2 signals. Legacy collection remains above because schema-v1
        // helpers still need the original values during migration recovery.
        for (const auto &[name, value] : windowsSchemaV2Factors())
        {
            // Native sources define the cross-language representation. CIM is
            // fallback/enrichment only and must never overwrite a value just
            // because PowerShell happened to work on this launch.
            if (factors.count(name) == 0)
                put(factors, name, value);
        }

        return factors;
    }

#elif defined(__APPLE__)

    std::map<std::string, std::string> collectFactors(std::string &error)
    {
        std::map<std::string, std::string> factors;

        const std::string expert = popenCapture("ioreg -rd1 -c IOPlatformExpertDevice");
        if (const auto uuid = firstMatch("\"IOPlatformUUID\"\\s*=\\s*\"([^\"]+)\"", expert); !uuid.empty())
            factors["machine_guid"] = uuid;
        if (const auto serial = firstMatch("\"IOPlatformSerialNumber\"\\s*=\\s*\"([^\"]+)\"", expert); !serial.empty())
        {
            factors["board_serial"] = serial;
            factors["system_serial"] = serial;
        }

        std::string brand = trim(popenCapture("sysctl -n machdep.cpu.brand_string"));
        if (brand.empty())
            brand = trim(popenCapture("sysctl -n hw.model"));
        const std::string cores = trim(popenCapture("sysctl -n hw.physicalcpu"));
        if (!brand.empty() && !cores.empty())
            factors["cpu_id"] = brand + "-" + cores;

        if (const auto mac = firstMatch("ether\\s+([0-9a-fA-F:]{17})", popenCapture("ifconfig en0")); !mac.empty())
            factors["mac"] = mac;
        if (const auto addresses = allMatches("Ethernet Address:\\s*([0-9a-fA-F:]{17})",
                                              popenCapture("networksetup -listallhardwareports"));
            !addresses.empty())
            factors["nic_identity"] = multiInstance(addresses);

        if (const auto total = trim(popenCapture("sysctl -n hw.memsize")); !total.empty())
            factors["ram_total"] = total;

        if (const auto uuid =
                firstMatch("<key>VolumeUUID</key>\\s*<string>([^<]+)</string>", popenCapture("diskutil info -plist /"));
            !uuid.empty())
            factors["volume_id"] = uuid;

        std::string computerName = trim(popenCapture("scutil --get ComputerName"));
        if (computerName.empty())
            computerName = trim(popenCapture("scutil --get LocalHostName"));
        if (!computerName.empty())
            factors["computer_name"] = computerName;

        if (const auto bootrom = firstMatch("\"spmachine_bootrom_version\"\\s*:\\s*\"([^\"]+)\"",
                                            popenCapture("system_profiler SPHardwareDataType -json"));
            !bootrom.empty())
            factors["firmware"] = bootrom;
        if (const auto serials = allMatches("\"[^\"]*serial[^\"]*\"\\s*:\\s*\"([^\"]+)\"",
                                            popenCapture("system_profiler SPMemoryDataType -json"));
            !serials.empty())
            factors["memory_modules"] = multiInstance(serials);
        const auto battery = popenCapture("ioreg -r -c AppleSmartBattery");
        std::string batterySerial = firstMatch("\"BatterySerialNumber\"\\s*=\\s*\"([^\"]+)\"", battery);
        if (batterySerial.empty())
            batterySerial = firstMatch("\"Serial\"\\s*=\\s*\"?([^\"\\n]+)\"?", battery);
        if (!batterySerial.empty())
            factors["battery_serial"] = batterySerial;

        if (const auto models = allMatches("\"spdisplays_model\"\\s*:\\s*\"([^\"]+)\"",
                                           popenCapture("system_profiler SPDisplaysDataType -json"));
            !models.empty())
            factors["gpu_id"] = multiInstance(models);

        if (const auto serials = allMatches("\"[a-z_]*serial[a-z_]*\"\\s*:\\s*\"([^\"]+)\"",
                                            popenCapture("system_profiler SPStorageDataType -json"));
            !serials.empty())
            factors["disk_serial"] = multiInstance(serials);

        if (const auto blobs = allMatches("\"IODisplayEDID\"\\s*=\\s*<?([0-9a-fA-F]+)>?",
                                          popenCapture("ioreg -r -c IODisplayConnect"));
            !blobs.empty())
        {
            std::vector<std::string> lowered;
            for (const auto &blob : blobs)
                lowered.push_back(toLower(blob));
            factors["monitor_edid"] = multiInstance(lowered);
        }

        const std::string version = trim(popenCapture("sw_vers -productVersion"));
        const std::string build = trim(popenCapture("sw_vers -buildVersion"));
        if (!version.empty() && !build.empty())
            factors["os_build"] = version + "-" + build;

        if (factors.empty())
            error = "slhwid: no hardware factors available on this machine";
        return factors;
    }

#elif defined(__linux__)

    namespace
    {
    std::optional<std::string> firstPhysicalMac()
    {
        std::error_code ec;
        for (const auto &entry : std::filesystem::directory_iterator("/sys/class/net", ec))
        {
            const std::string name = entry.path().filename().string();
            if (name == "lo" || name.rfind("veth", 0) == 0 || name.rfind("docker", 0) == 0 ||
                name.rfind("virbr", 0) == 0 || name.rfind("tun", 0) == 0 || name.rfind("tap", 0) == 0 ||
                name.rfind("zt", 0) == 0 || name.rfind("tailscale", 0) == 0)
                continue;
            if (const auto address = readFileTrimmed("/sys/class/net/" + name + "/address");
                address && *address != "00:00:00:00:00:00")
                return *address;
        }
        return std::nullopt;
    }
    } // namespace

    std::map<std::string, std::string> collectFactors(std::string &error)
    {
        std::map<std::string, std::string> factors;

        for (const auto &[slot, path] : std::initializer_list<std::pair<const char *, const char *>>{
                 {"machine_guid", "/etc/machine-id"},
                 {"board_serial", "/sys/class/dmi/id/board_serial"},
                 {"product_uuid", "/sys/class/dmi/id/product_uuid"},
                 {"firmware", "/sys/class/dmi/id/bios_version"},
             })
        {
            if (const auto value = readFileTrimmed(path))
                factors[slot] = *value;
        }
        if (const auto value = readFileTrimmed("/sys/class/dmi/id/product_uuid"))
            factors["system_uuid"] = *value;
        if (const auto value = readFileTrimmed("/sys/class/dmi/id/product_serial"))
            factors["system_serial"] = *value;
        if (const auto value = readFileTrimmed("/sys/class/dmi/id/chassis_serial"))
            factors["chassis_serial"] = *value;
        if (const auto serials =
                allMatches("Serial Number:\\s*([^\\r\\n]+)", popenCapture("dmidecode --type memory 2>/dev/null"));
            !serials.empty())
            factors["memory_modules"] = multiInstance(serials);

        std::vector<std::string> nicIdentities;
        std::error_code factorEc;
        for (const auto &entry : std::filesystem::directory_iterator("/sys/class/net", factorEc))
        {
            if (!std::filesystem::exists(entry.path() / "device", factorEc))
                continue;
            if (const auto address = readFileTrimmed((entry.path() / "perm_address").string());
                address && *address != "00:00:00:00:00:00")
                nicIdentities.push_back(*address);
        }
        if (!nicIdentities.empty())
            factors["nic_identity"] = multiInstance(nicIdentities);

        std::vector<std::string> batterySerials;
        for (const auto &entry : std::filesystem::directory_iterator("/sys/class/power_supply", factorEc))
        {
            if (entry.path().filename().string().rfind("BAT", 0) != 0)
                continue;
            if (const auto serial = readFileTrimmed((entry.path() / "serial_number").string()))
                batterySerials.push_back(*serial);
        }
        if (!batterySerials.empty())
            factors["battery_serial"] = multiInstance(batterySerials);

        for (const auto &path : {"/sys/class/tpm/tpm0/device/ek_pub", "/sys/class/tpm/tpm0/ek_pub"})
        {
            std::ifstream ek(path, std::ios::binary);
            if (!ek)
                continue;
            std::vector<unsigned char> data((std::istreambuf_iterator<char>(ek)), std::istreambuf_iterator<char>());
            if (!data.empty())
            {
                factors["tpm_ek"] = toLowerHex(sha256(data));
                break;
            }
        }
        {
            std::ifstream cpuinfo("/proc/cpuinfo");
            std::string content((std::istreambuf_iterator<char>(cpuinfo)), std::istreambuf_iterator<char>());
            if (const auto serial = firstMatch("Serial\\s*:\\s*([0-9a-f]+)", content); !serial.empty())
                factors["cpu_id"] = serial;
        }
        if (const auto disk = readFileTrimmed("/sys/block/sda/device/serial"))
            factors["disk_serial"] = *disk;

        char hostname[256] = {};
        if (::gethostname(hostname, sizeof(hostname)) == 0 && hostname[0] != 0)
            factors["computer_name"] = hostname;

        if (const auto meminfo = readFileTrimmed("/proc/meminfo"))
        {
            if (const auto match = firstMatch("MemTotal:\\s+(\\d+)\\s+kB", *meminfo); !match.empty())
                factors["ram_total"] = std::to_string(std::stoull(match) * 1024);
        }

        if (const auto uuid = trim(popenCapture("findmnt -no UUID /")); !uuid.empty())
            factors["volume_id"] = uuid;

        if (const auto osRelease = readFileTrimmed("/etc/os-release"))
        {
            if (const auto pretty = firstMatch("^PRETTY_NAME=\"?([^\"\\n]+)\"?", *osRelease); !pretty.empty())
                factors["os_build"] = pretty;
        }

        std::vector<std::string> blobs;
        std::error_code ec;
        for (const auto &entry : std::filesystem::directory_iterator("/sys/class/drm", ec))
        {
            const std::string name = entry.path().filename().string();
            if (name.rfind("card", 0) != 0 || name.find('-') == std::string::npos)
                continue;
            std::ifstream file(entry.path() / "edid", std::ios::binary);
            if (!file)
                continue;
            std::vector<unsigned char> data((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
            if (!data.empty())
                blobs.push_back(toLowerHex(data));
        }
        if (!blobs.empty())
            factors["monitor_edid"] = multiInstance(blobs);

        std::vector<std::string> gpus;
        for (const auto &entry : std::filesystem::directory_iterator("/sys/bus/pci/devices", ec))
        {
            if (const auto klass = readFileTrimmed((entry.path() / "class").string()); klass && klass->rfind("0x03", 0) == 0)
            {
                const auto vendor = readFileTrimmed((entry.path() / "vendor").string());
                const auto device = readFileTrimmed((entry.path() / "device").string());
                if (vendor && device)
                    gpus.push_back(*vendor + ":" + *device);
            }
        }
        if (!gpus.empty())
            factors["gpu_id"] = multiInstance(gpus);

        if (const auto mac = firstPhysicalMac())
            factors["mac"] = *mac;

        return factors;
    }

#else

    std::map<std::string, std::string> collectFactors(std::string &error)
    {
        error = "slhwid: secret-sharing HWID is not supported on this platform";
        return {};
    }

#endif
}
