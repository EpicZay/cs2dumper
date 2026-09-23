#pragma once
#include <cstdint>
#include <filesystem>
#include <optional>
#include <span>
#include <string>
#include <vector>
#ifdef _WIN32
#include <windows.h>
#endif

namespace cs2 {
struct LoadedModule {
    std::string name;
    std::filesystem::path path;
    std::uint64_t base{};
    std::uint32_t size{};
};
class MemoryReader {
  public:
    virtual ~MemoryReader() = default;
    virtual bool read(std::uint64_t address, std::span<std::uint8_t> out) const = 0;
    template <class T> std::optional<T> value(std::uint64_t address) const {
        T result{};
        if (!read(address, {reinterpret_cast<std::uint8_t *>(&result), sizeof(result)}))
            return std::nullopt;
        return result;
    }
    std::optional<std::string> string(std::uint64_t address, std::size_t limit = 128) const;
};
class ProcessReader final : public MemoryReader {
  public:
    ProcessReader() = default;
    ~ProcessReader();
    ProcessReader(const ProcessReader &) = delete;
    ProcessReader &operator=(const ProcessReader &) = delete;
    bool attach(std::uint32_t pid, std::string &error);
    bool read(std::uint64_t address, std::span<std::uint8_t> out) const override;
    std::vector<LoadedModule> modules(std::string &error) const;
    static std::optional<std::uint32_t> find_pid(std::wstring_view name);
    bool attached() const {
        return handle_ != nullptr;
    }

  private:
#ifdef _WIN32
    HANDLE handle_{};
#else
    void *handle_{};
#endif
    std::uint32_t pid_{};
};
} // namespace cs2
