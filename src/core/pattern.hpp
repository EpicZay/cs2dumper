#pragma once
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace cs2 {
struct PatternByte {
    std::uint8_t value{};
    bool wildcard{};
};
struct Pattern {
    std::vector<PatternByte> bytes;
};
enum class ScanStatus { success, not_found, multiple_matches, invalid_pattern, invalid_module, invalid_instruction };
struct ScanResult {
    ScanStatus status{ScanStatus::not_found};
    std::size_t offset{};
    std::size_t matches{};
    std::string error;
};

std::optional<Pattern> compile_pattern(std::string_view text, std::string &error);
ScanResult scan_unique(std::span<const std::uint8_t> data, const Pattern &pattern);
std::optional<std::uint64_t> resolve_relative(std::uint64_t address, std::span<const std::uint8_t> instruction,
                                              std::size_t displacement_offset, std::size_t instruction_length);
std::optional<std::uint64_t> resolve_relative_call(std::uint64_t address, std::span<const std::uint8_t> instruction);
std::optional<std::uint64_t> resolve_relative_jump(std::uint64_t address, std::span<const std::uint8_t> instruction);
} // namespace cs2
