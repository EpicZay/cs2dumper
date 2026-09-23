#include "core/pe.hpp"
#include <algorithm>
#include <cstring>
#include <fstream>
#include <iterator>
#include <limits>

namespace cs2 {
namespace {
template <class T> std::optional<T> number(std::span<const std::uint8_t> b, std::size_t at) {
    if (at > b.size() || b.size() - at < sizeof(T))
        return std::nullopt;
    T n{};
    std::memcpy(&n, b.data() + at, sizeof(T));
    return n;
}
std::string cstr(std::span<const std::uint8_t> b, std::size_t at, std::size_t max = 256) {
    if (at >= b.size())
        return {};
    const auto end = std::min(b.size(), at + max);
    auto i = at;
    while (i < end && b[i])
        ++i;
    return i == end ? std::string{} : std::string(reinterpret_cast<const char *>(b.data() + at), i - at);
}
} // namespace
std::span<const std::uint8_t> PeImage::at(std::uint32_t rva, std::size_t count) const {
    if (rva > bytes_.size() || count > bytes_.size() - rva)
        return {};
    return {bytes_.data() + rva, count};
}
std::optional<PeSection> PeImage::section(std::string_view name) const {
    for (const auto &s : sections_)
        if (s.name == name)
            return s;
    return std::nullopt;
}
std::optional<PeImage> PeImage::from_mapped(std::vector<std::uint8_t> image, std::string &error) {
    PeImage pe;
    pe.bytes_ = std::move(image);
    if (!pe.parse(error))
        return std::nullopt;
    return pe;
}
std::optional<PeImage> PeImage::from_file(const std::filesystem::path &path, std::string &error) {
    std::ifstream stream(path, std::ios::binary);
    if (!stream) {
        error = "cannot open PE file";
        return std::nullopt;
    }
    std::vector<std::uint8_t> raw{std::istreambuf_iterator<char>(stream), std::istreambuf_iterator<char>()};
    const auto b = std::span<const std::uint8_t>(raw);
    const auto lfanew = number<std::uint32_t>(b, 0x3c);
    if (raw.size() < 0x40 || raw[0] != 'M' || raw[1] != 'Z' || !lfanew || *lfanew > raw.size() ||
        raw.size() - *lfanew < 0x108 || !number<std::uint32_t>(b, *lfanew) ||
        *number<std::uint32_t>(b, *lfanew) != 0x4550) {
        error = "invalid PE headers";
        return std::nullopt;
    }
    const auto opt = static_cast<std::size_t>(*lfanew) + 24;
    const auto size = number<std::uint32_t>(b, opt + 56);
    const auto headers = number<std::uint32_t>(b, opt + 60);
    const auto count = number<std::uint16_t>(b, *lfanew + 6);
    const auto opt_size = number<std::uint16_t>(b, *lfanew + 20);
    if (!size || !headers || !count || !opt_size || *size == 0 || *size > (1u << 29) || *headers > raw.size() ||
        *headers > *size || *count > 96) {
        error = "invalid PE dimensions";
        return std::nullopt;
    }
    std::vector<std::uint8_t> mapped(*size);
    std::copy_n(raw.begin(), *headers, mapped.begin());
    const std::size_t table = opt + *opt_size;
    if (table > raw.size() || *count > (raw.size() - table) / 40) {
        error = "section table outside PE file";
        return std::nullopt;
    }
    for (std::size_t i = 0; i < *count; ++i) {
        const auto sh = table + i * 40;
        const auto rva = number<std::uint32_t>(b, sh + 12);
        const auto raw_size = number<std::uint32_t>(b, sh + 16);
        const auto raw_ptr = number<std::uint32_t>(b, sh + 20);
        if (!rva || !raw_size || !raw_ptr || *rva > mapped.size() || *raw_size > mapped.size() - *rva ||
            *raw_ptr > raw.size() || *raw_size > raw.size() - *raw_ptr) {
            error = "section outside PE image";
            return std::nullopt;
        }
        std::copy_n(raw.begin() + *raw_ptr, *raw_size, mapped.begin() + *rva);
    }
    return from_mapped(std::move(mapped), error);
}
bool PeImage::parse(std::string &error) {
    auto b = bytes();
    const auto lfanew = number<std::uint32_t>(b, 0x3c);
    if (b.size() < 0x40 || b[0] != 'M' || b[1] != 'Z' || !lfanew || !number<std::uint32_t>(b, *lfanew) ||
        *number<std::uint32_t>(b, *lfanew) != 0x4550) {
        error = "invalid DOS/NT signature";
        return false;
    }
    const std::size_t coff = static_cast<std::size_t>(*lfanew) + 4;
    const auto count = number<std::uint16_t>(b, coff + 2);
    const auto opt_size = number<std::uint16_t>(b, coff + 16);
    const auto opt = coff + 20;
    const auto magic = number<std::uint16_t>(b, opt);
    const auto size = number<std::uint32_t>(b, opt + 56);
    if (!count || !opt_size || !magic || *magic != 0x20b || !size || *size > b.size() || *size == 0 || *count > 96 ||
        opt + *opt_size > b.size() || *opt_size < 0x70) {
        error = "invalid PE32+ optional header";
        return false;
    }
    image_size_ = *size;
    machine_ = *number<std::uint16_t>(b, coff);
    timestamp_ = *number<std::uint32_t>(b, coff + 4);
    const std::size_t table = opt + *opt_size;
    if (table > b.size() || *count > (b.size() - table) / 40) {
        error = "invalid section table";
        return false;
    }
    for (std::size_t i = 0; i < *count; ++i) {
        const std::size_t sh = table + i * 40;
        auto name = cstr(b.subspan(sh, 8), 0, 8);
        if (name.empty()) {
            const auto end = std::find(b.begin() + sh, b.begin() + sh + 8, 0);
            name.assign(reinterpret_cast<const char *>(b.data() + sh), end - (b.begin() + sh));
        }
        PeSection s{name, *number<std::uint32_t>(b, sh + 12), *number<std::uint32_t>(b, sh + 8),
                    *number<std::uint32_t>(b, sh + 16), *number<std::uint32_t>(b, sh + 36)};
        if (s.rva > image_size_ || std::max(s.virtual_size, s.raw_size) > image_size_ - s.rva) {
            error = "invalid section bounds";
            return false;
        }
        sections_.push_back(std::move(s));
    }
    if (*opt_size >= 0x78) {
        const auto export_rva = number<std::uint32_t>(b, opt + 112);
        const auto export_size = number<std::uint32_t>(b, opt + 116);
        if (export_rva && export_size && *export_rva && *export_size && at(*export_rva, 40).size() == 40) {
            const auto dir = static_cast<std::size_t>(*export_rva);
            const auto names = number<std::uint32_t>(b, dir + 24);
            const auto funcs_rva = number<std::uint32_t>(b, dir + 28);
            const auto names_rva = number<std::uint32_t>(b, dir + 32);
            const auto ords_rva = number<std::uint32_t>(b, dir + 36);
            const auto nfuncs = number<std::uint32_t>(b, dir + 20);
            if (names && funcs_rva && names_rva && ords_rva && nfuncs && *names < 100000 && *nfuncs < 100000 &&
                at(*names_rva, static_cast<std::size_t>(*names) * 4).size() == static_cast<std::size_t>(*names) * 4 &&
                at(*ords_rva, static_cast<std::size_t>(*names) * 2).size() == static_cast<std::size_t>(*names) * 2 &&
                at(*funcs_rva, static_cast<std::size_t>(*nfuncs) * 4).size() == static_cast<std::size_t>(*nfuncs) * 4) {
                for (std::size_t i = 0; i < *names; ++i) {
                    const auto nrva = number<std::uint32_t>(b, *names_rva + i * 4);
                    const auto ordinal = number<std::uint16_t>(b, *ords_rva + i * 2);
                    if (!nrva || !ordinal || *ordinal >= *nfuncs)
                        continue;
                    const auto frva = number<std::uint32_t>(b, *funcs_rva + *ordinal * 4);
                    if (!frva || *frva >= image_size_)
                        continue;
                    const auto name = cstr(b, *nrva);
                    if (!name.empty())
                        exports_.push_back(
                            {name, *frva,
                             *frva >= *export_rva && static_cast<std::uint64_t>(*frva) <
                                                         static_cast<std::uint64_t>(*export_rva) + *export_size});
                }
            }
        }
    }
    std::sort(exports_.begin(), exports_.end(), [](const auto &a, const auto &b) { return a.name < b.name; });
    return true;
}
} // namespace cs2
