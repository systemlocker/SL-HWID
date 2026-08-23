#define _CRT_SECURE_NO_WARNINGS
// SL-HWID platform layer: default storage (Windows registry with an HKCU
// fallback; owner-only files elsewhere) and factor collectors. Every source
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
#include <optional>
#include <regex>
#include <sstream>
#include <sys/stat.h>
#include <thread>

#if defined(_WIN32)
#include <windows.h>
#include <bcrypt.h>
#else
#include <cerrno>
#include <fcntl.h>
#include <signal.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fstream>

#if defined(__linux__)
#include <filesystem>
#include <sys/random.h>
#endif
#endif

namespace slhwid::detail
{
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
        std::string popenCapture(const std::string &command)
        {
            std::string output;
            FILE *pipe = ::_popen(command.c_str(), "r");
            if (pipe == nullptr)
                return "";
            char buffer[4096];
            while (std::fgets(buffer, sizeof(buffer), pipe) != nullptr)
                output += buffer;
            ::_pclose(pipe);
            return output;
        }

        void mkdirForPath(const std::string &directory)
        {
            CreateDirectoryA(directory.c_str(), nullptr);
        }
#else
        std::string popenCapture(const std::string &command)
        {
            std::string output;
            FILE *pipe = ::popen(command.c_str(), "r");
            if (pipe == nullptr)
                return "";
            char buffer[4096];
            while (std::fgets(buffer, sizeof(buffer), pipe) != nullptr)
                output += buffer;
            ::pclose(pipe);
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
                Read result;
                for (const HKEY root : {HKEY_LOCAL_MACHINE, HKEY_CURRENT_USER})
                {
                    HKEY handle;
                    if (RegOpenKeyExA(root, "SOFTWARE\\SystemLocker", 0,
                                      KEY_READ | KEY_WOW64_64KEY, &handle) != ERROR_SUCCESS)
                        continue;
                    DWORD type = 0;
                    DWORD size = 0;
                    if (RegQueryValueExA(handle, key.c_str(), nullptr, &type, nullptr, &size) != ERROR_SUCCESS ||
                        type != REG_BINARY)
                    {
                        RegCloseKey(handle);
                        continue;
                    }
                    std::vector<unsigned char> data(size);
                    if (RegQueryValueExA(handle, key.c_str(), nullptr, nullptr, data.data(), &size) == ERROR_SUCCESS)
                    {
                        data.resize(size);
                        result.data = std::move(data);
                        RegCloseKey(handle);
                        return result;
                    }
                    RegCloseKey(handle);
                }
                return result; // absent everywhere
            }

            bool write(const std::string &key, const std::vector<unsigned char> &data, std::string &error) override
            {
                for (const HKEY root : {HKEY_LOCAL_MACHINE, HKEY_CURRENT_USER})
                {
                    HKEY handle;
                    if (RegCreateKeyExA(root, "SOFTWARE\\SystemLocker", 0, nullptr, REG_OPTION_NON_VOLATILE,
                                        KEY_SET_VALUE | KEY_WOW64_64KEY, nullptr, &handle, nullptr) != ERROR_SUCCESS)
                        continue;
                    const LSTATUS status = RegSetValueExA(handle, key.c_str(), 0, REG_BINARY,
                                                          data.data(), static_cast<DWORD>(data.size()));
                    RegCloseKey(handle);
                    if (status == ERROR_SUCCESS)
                        return true;
                }
                error = "slhwid: registry write failed";
                return false;
            }

            std::string lockDirectory() const override { return localLockDirectory(); }
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
        std::optional<std::string> registryValue(const std::string &path, const std::string &name)
        {
            HKEY handle;
            if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, path.c_str(), 0,
                              KEY_READ | KEY_WOW64_64KEY, &handle) != ERROR_SUCCESS)
                return std::nullopt;
            DWORD type = 0;
            DWORD size = 0;
            if (RegQueryValueExA(handle, name.c_str(), nullptr, &type, nullptr, &size) != ERROR_SUCCESS)
            {
                RegCloseKey(handle);
                return std::nullopt;
            }
            std::string value;
            if (type == REG_SZ || type == REG_EXPAND_SZ)
            {
                std::vector<char> buffer(size + 1, 0);
                if (RegQueryValueExA(handle, name.c_str(), nullptr, nullptr,
                                     reinterpret_cast<LPBYTE>(buffer.data()), &size) != ERROR_SUCCESS)
                {
                    RegCloseKey(handle);
                    return std::nullopt;
                }
                value.assign(buffer.data(), std::strlen(buffer.data()));
            }
            else if (type == REG_MULTI_SZ)
            {
                std::vector<char> buffer(size + 2, 0);
                if (RegQueryValueExA(handle, name.c_str(), nullptr, nullptr,
                                     reinterpret_cast<LPBYTE>(buffer.data()), &size) != ERROR_SUCCESS)
                {
                    RegCloseKey(handle);
                    return std::nullopt;
                }
                for (std::size_t i = 0; i < size && buffer[i] != 0;)
                {
                    const std::string part(buffer.data() + i);
                    if (!value.empty())
                        value += " ";
                    value += part;
                    i += part.size() + 1;
                }
            }
            else if (type == REG_DWORD)
            {
                DWORD number = 0;
                DWORD dwordSize = sizeof(number);
                if (RegQueryValueExA(handle, name.c_str(), nullptr, nullptr,
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
            HKEY handle;
            if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, path.c_str(), 0,
                              KEY_READ | KEY_WOW64_64KEY, &handle) != ERROR_SUCCESS)
                return names;
            char name[256];
            for (DWORD index = 0;; ++index)
            {
                DWORD nameSize = sizeof(name);
                if (RegEnumKeyExA(handle, index, name, &nameSize, nullptr, nullptr, nullptr, nullptr) != ERROR_SUCCESS)
                    break;
                names.emplace_back(name, nameSize);
            }
            RegCloseKey(handle);
            std::sort(names.begin(), names.end());
            return names;
        }

        std::optional<std::vector<unsigned char>> registryBinary(const std::string &path, const std::string &name)
        {
            HKEY handle;
            if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, path.c_str(), 0,
                              KEY_READ | KEY_WOW64_64KEY, &handle) != ERROR_SUCCESS)
                return std::nullopt;
            DWORD type = 0;
            DWORD size = 0;
            if (RegQueryValueExA(handle, name.c_str(), nullptr, &type, nullptr, &size) != ERROR_SUCCESS ||
                type != REG_BINARY)
            {
                RegCloseKey(handle);
                return std::nullopt;
            }
            std::vector<unsigned char> data(size);
            if (RegQueryValueExA(handle, name.c_str(), nullptr, nullptr, data.data(), &size) != ERROR_SUCCESS)
                data.clear();
            else
                data.resize(size);
            RegCloseKey(handle);
            return data;
        }

        void put(std::map<std::string, std::string> &factors, const std::string &slot, const std::optional<std::string> &value)
        {
            if (value && !value->empty())
                factors[slot] = *value;
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

        if (const char *computerName = std::getenv("COMPUTERNAME"))
            factors["computer_name"] = computerName;

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

        std::vector<std::string> diskSerials;
        {
            std::istringstream lines(popenCapture("wmic diskdrive get SerialNumber 2>nul"));
            std::string line;
            while (std::getline(lines, line))
            {
                line = trim(line);
                if (!line.empty() && toLower(line) != "serialnumber")
                    diskSerials.push_back(line);
            }
        }
        put(factors, "disk_serial", multiInstance(diskSerials));

        {
            MEMORYSTATUSEX status{};
            status.dwLength = sizeof(status);
            if (GlobalMemoryStatusEx(&status))
                factors["ram_total"] = std::to_string(status.ullTotalPhys);
        }

        {
            const char *drive = std::getenv("SystemDrive");
            const auto output = popenCapture(std::string("cmd /c vol ") + (drive != nullptr ? drive : "C:"));
            const auto matches = allMatches("([0-9A-Fa-f]{4}-[0-9A-Fa-f]{4})", output);
            if (!matches.empty())
                factors["volume_id"] = matches.back();
        }

        {
            // getmac's CSV columns are locale-stable; the physical-address
            // format is fixed.
            const auto output = popenCapture("getmac /fo csv /nh");
            const auto rows = allMatches(
                "([0-9A-Fa-f]{2}-[0-9A-Fa-f]{2}-[0-9A-Fa-f]{2}-[0-9A-Fa-f]{2}-[0-9A-Fa-f]{2}-[0-9A-Fa-f]{2})([^\\r\\n]*)",
                output);
            for (const auto &row : rows)
            {
                const std::string rest = toLower(row.substr(17));
                if (rest.find("teredo") != std::string::npos || rest.find("isatap") != std::string::npos ||
                    rest.find("vethernet") != std::string::npos || rest.find("vmware") != std::string::npos ||
                    rest.find("wsl") != std::string::npos || rest.find("docker") != std::string::npos ||
                    rest.find("bluetooth") != std::string::npos || rest.find("tailscale") != std::string::npos ||
                    rest.find("vpn") != std::string::npos)
                    continue;
                std::string mac = row.substr(0, 17);
                mac.erase(std::remove(mac.begin(), mac.end(), '-'), mac.end());
                factors["mac"] = mac;
                break;
            }
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
            factors["board_serial"] = serial;

        std::string brand = trim(popenCapture("sysctl -n machdep.cpu.brand_string"));
        if (brand.empty())
            brand = trim(popenCapture("sysctl -n hw.model"));
        const std::string cores = trim(popenCapture("sysctl -n hw.physicalcpu"));
        if (!brand.empty() && !cores.empty())
            factors["cpu_id"] = brand + "-" + cores;

        if (const auto mac = firstMatch("ether\\s+([0-9a-fA-F:]{17})", popenCapture("ifconfig en0")); !mac.empty())
            factors["mac"] = mac;

        if (const auto total = trim(popenCapture("sysctl -n hw.memsize")); !total.empty())
            factors["ram_total"] = total;

        if (const auto uuid = firstMatch("<key>VolumeUUID</key>\\s*<string>([^<]+)</string>", popenCapture("diskutil info -plist /")); !uuid.empty())
            factors["volume_id"] = uuid;

        std::string computerName = trim(popenCapture("scutil --get ComputerName"));
        if (computerName.empty())
            computerName = trim(popenCapture("scutil --get LocalHostName"));
        if (!computerName.empty())
            factors["computer_name"] = computerName;

        if (const auto bootrom = firstMatch("\"spmachine_bootrom_version\"\\s*:\\s*\"([^\"]+)\"", popenCapture("system_profiler SPHardwareDataType -json")); !bootrom.empty())
            factors["firmware"] = bootrom;

        if (const auto models = allMatches("\"spdisplays_model\"\\s*:\\s*\"([^\"]+)\"", popenCapture("system_profiler SPDisplaysDataType -json")); !models.empty())
            factors["gpu_id"] = multiInstance(models);

        if (const auto serials = allMatches("\"[a-z_]*serial[a-z_]*\"\\s*:\\s*\"([^\"]+)\"", popenCapture("system_profiler SPStorageDataType -json")); !serials.empty())
            factors["disk_serial"] = multiInstance(serials);

        if (const auto blobs = allMatches("\"IODisplayEDID\"\\s*=\\s*<?([0-9a-fA-F]+)>?", popenCapture("ioreg -r -c IODisplayConnect")); !blobs.empty())
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
    }

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
