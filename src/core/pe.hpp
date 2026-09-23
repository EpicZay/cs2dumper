#pragma once
#include <cstdint>
#include <filesystem>
#include <optional>
#include <span>
#include <string>
#include <vector>

namespace cs2 {
struct PeSection {
    std::string name;
    std::uint32_t rva{}, virtual_size{}, raw_size{}, characteristics{};
};
struct PeExport {
    std::string name;
    std::uint32_t rva{};
    bool forwarded{};
};
class PeImage {
  public:
    static std::optional<PeImage> from_mapped(std::vector<std::uint8_t> image, std::string &error);
    static std::optional<PeImage> from_file(const std::filesystem::path &path, std::string &error);
    std::span<const std::uint8_t> bytes() const {
        return bytes_;
    }
    std::span<const std::uint8_t> at(std::uint32_t rva, std::size_t count) const;
    std::optional<PeSection> section(std::string_view name) const;
    const std::vector<PeSection> &sections() const {
        return sections_;
    }
    const std::vector<PeExport> &exports() const {
        return exports_;
    }
    std::uint32_t image_size() const {
        return image_size_;
    }
    std::uint32_t timestamp() const {
        return timestamp_;
    }
    std::uint16_t machine() const {
        return machine_;
    }

  private:
    bool parse(std::string &error);
    std::vector<std::uint8_t> bytes_;
    std::vector<PeSection> sections_;
    std::vector<PeExport> exports_;
    std::uint32_t image_size_{}, timestamp_{};
    std::uint16_t machine_{};
};
} // namespace cs2
