#include "core/process.hpp"
#include <algorithm>
#include <cctype>
#ifdef _WIN32
#include <tlhelp32.h>
#endif

namespace cs2 {
std::optional<std::string> MemoryReader::string(std::uint64_t address, std::size_t limit) const {
    if (!address || limit == 0 || limit > 4096)
        return std::nullopt;
    std::string result;
    result.reserve(std::min<std::size_t>(limit, 128));
    for (std::size_t i = 0; i < limit; ++i) {
        const auto c = value<std::uint8_t>(address + i);
        if (!c)
            return std::nullopt;
        if (!*c)
            return result;
        if (*c < 0x20 || *c > 0x7e)
            return std::nullopt;
        result.push_back(static_cast<char>(*c));
    }
    return std::nullopt;
}
ProcessReader::~ProcessReader() {
#ifdef _WIN32
    if (handle_)
        CloseHandle(handle_);
#endif
}
bool ProcessReader::attach(std::uint32_t pid, std::string &error) {
#ifdef _WIN32
    if (handle_)
        CloseHandle(handle_);
    handle_ = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (!handle_) {
        error = "OpenProcess read-only failed (Windows error " + std::to_string(GetLastError()) + ")";
        return false;
    }
    pid_ = pid;
    return true;
#else
    (void)pid;
    error = "live process reading is supported on Windows only";
    return false;
#endif
}
bool ProcessReader::read(std::uint64_t address, std::span<std::uint8_t> out) const {
#ifdef _WIN32
    if (!handle_ || !address || out.empty())
        return false;
    SIZE_T count{};
    return ReadProcessMemory(handle_, reinterpret_cast<LPCVOID>(static_cast<std::uintptr_t>(address)), out.data(),
                             out.size(), &count) &&
           count == out.size();
#else
    (void)address;
    (void)out;
    return false;
#endif
}
std::optional<std::uint32_t> ProcessReader::find_pid(std::wstring_view name) {
#ifdef _WIN32
    const HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE)
        return std::nullopt;
    PROCESSENTRY32W entry{};
    entry.dwSize = sizeof(entry);
    std::optional<std::uint32_t> result;
    if (Process32FirstW(snapshot, &entry))
        do {
            if (name == entry.szExeFile) {
                result = entry.th32ProcessID;
                break;
            }
        } while (Process32NextW(snapshot, &entry));
    CloseHandle(snapshot);
    return result;
#else
    (void)name;
    return std::nullopt;
#endif
}
std::vector<LoadedModule> ProcessReader::modules(std::string &error) const {
    std::vector<LoadedModule> result;
#ifdef _WIN32
    if (!handle_) {
        error = "process is not attached";
        return result;
    }
    const HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid_);
    if (snapshot == INVALID_HANDLE_VALUE) {
        error = "module snapshot failed (Windows error " + std::to_string(GetLastError()) + ")";
        return result;
    }
    MODULEENTRY32W entry{};
    entry.dwSize = sizeof(entry);
    if (Module32FirstW(snapshot, &entry))
        do {
            auto narrow = [](const wchar_t *wide) {
                std::string s;
                for (; *wide; ++wide)
                    s.push_back(*wide < 128 ? static_cast<char>(*wide) : '?');
                return s;
            };
            std::string name = narrow(entry.szModule);
            std::transform(name.begin(), name.end(), name.begin(),
                           [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
            result.push_back(
                {name, entry.szExePath, reinterpret_cast<std::uint64_t>(entry.modBaseAddr), entry.modBaseSize});
        } while (Module32NextW(snapshot, &entry));
    CloseHandle(snapshot);
    if (result.empty())
        error = "module snapshot was empty";
#else
    error = "live module enumeration is supported on Windows only";
#endif
    return result;
}
} // namespace cs2
