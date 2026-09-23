#include "core/pattern.hpp"
#include <charconv>
#include <cstring>
#include <limits>

namespace cs2 {
std::optional<Pattern> compile_pattern(std::string_view text, std::string &error) {
    Pattern result;
    std::size_t pos = 0;
    while (pos < text.size()) {
        while (pos < text.size() && (text[pos] == ' ' || text[pos] == '\t'))
            ++pos;
        if (pos == text.size())
            break;
        const auto end = text.find_first_of(" \t", pos);
        const auto token = text.substr(pos, end == std::string_view::npos ? text.size() - pos : end - pos);
        if (token == "?" || token == "??")
            result.bytes.push_back({0, true});
        else {
            if (token.size() != 2) {
                error = "pattern token must be two hex digits or ?/??";
                return std::nullopt;
            }
            unsigned value{};
            const auto parsed = std::from_chars(token.data(), token.data() + token.size(), value, 16);
            if (parsed.ec != std::errc{} || parsed.ptr != token.data() + token.size() || value > 255) {
                error = "invalid hex byte in pattern";
                return std::nullopt;
            }
            result.bytes.push_back({static_cast<std::uint8_t>(value), false});
        }
        pos = end == std::string_view::npos ? text.size() : end;
    }
    if (result.bytes.empty()) {
        error = "empty pattern";
        return std::nullopt;
    }
    return result;
}

ScanResult scan_unique(std::span<const std::uint8_t> data, const Pattern &pattern) {
    if (pattern.bytes.empty())
        return {ScanStatus::invalid_pattern, 0, 0, "empty compiled pattern"};
    ScanResult result;
    if (pattern.bytes.size() > data.size())
        return result;
    for (std::size_t i = 0; i <= data.size() - pattern.bytes.size(); ++i) {
        bool match = true;
        for (std::size_t j = 0; j < pattern.bytes.size(); ++j)
            if (!pattern.bytes[j].wildcard && pattern.bytes[j].value != data[i + j]) {
                match = false;
                break;
            }
        if (match) {
            result.offset = i;
            ++result.matches;
        }
    }
    result.status = result.matches == 0   ? ScanStatus::not_found
                    : result.matches == 1 ? ScanStatus::success
                                          : ScanStatus::multiple_matches;
    if (result.matches > 1)
        result.error = "pattern has " + std::to_string(result.matches) + " matches";
    return result;
}

std::optional<std::uint64_t> resolve_relative(std::uint64_t address, std::span<const std::uint8_t> instruction,
                                              std::size_t displacement_offset, std::size_t instruction_length) {
    if (instruction_length > instruction.size() || displacement_offset > instruction_length ||
        instruction_length - displacement_offset < sizeof(std::int32_t))
        return std::nullopt;
    std::int32_t displacement{};
    std::memcpy(&displacement, instruction.data() + displacement_offset, sizeof(displacement));
    if (address > std::numeric_limits<std::uint64_t>::max() - instruction_length)
        return std::nullopt;
    const auto next = address + instruction_length;
    if (displacement >= 0) {
        if (next > std::numeric_limits<std::uint64_t>::max() - static_cast<std::uint32_t>(displacement))
            return std::nullopt;
        return next + static_cast<std::uint32_t>(displacement);
    }
    const auto magnitude = static_cast<std::uint64_t>(-static_cast<std::int64_t>(displacement));
    if (next < magnitude)
        return std::nullopt;
    return next - magnitude;
}
std::optional<std::uint64_t> resolve_relative_call(std::uint64_t address, std::span<const std::uint8_t> code) {
    if (code.size() < 5 || code[0] != 0xE8)
        return std::nullopt;
    return resolve_relative(address, code, 1, 5);
}
std::optional<std::uint64_t> resolve_relative_jump(std::uint64_t address, std::span<const std::uint8_t> code) {
    if (code.size() < 5 || code[0] != 0xE9)
        return std::nullopt;
    return resolve_relative(address, code, 1, 5);
}
} // namespace cs2
