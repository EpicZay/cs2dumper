#include "core/pattern.hpp"
#include "core/pe.hpp"
#include "database/database.hpp"
#include "generators/generator.hpp"
#include <chrono>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <functional>
#include <iostream>
#include <nlohmann/json.hpp>
#include <stdexcept>

using namespace cs2;
namespace fs = std::filesystem;
namespace {
void require(bool value, const char *message) {
    if (!value)
        throw std::runtime_error(message);
}
template <class T> void put(std::vector<std::uint8_t> &b, std::size_t at, T value) {
    require(at + sizeof(T) <= b.size(), "fake PE write out of bounds");
    std::memcpy(b.data() + at, &value, sizeof(T));
}
void pattern_parser_and_wildcard_matching() {
    std::string error;
    const auto pattern = compile_pattern("48 8B 0D ? ?? 00", error);
    require(pattern && pattern->bytes.size() == 6, "wildcard pattern parse failed");
    const std::vector<std::uint8_t> image{0x90, 0x48, 0x8B, 0x0D, 0xAA, 0xBB, 0x00, 0x90};
    const auto found = scan_unique(image, *pattern);
    require(found.status == ScanStatus::success && found.offset == 1 && found.matches == 1,
            "unique wildcard scan failed");
    require(scan_unique(std::span<const std::uint8_t>(image).first(3), *pattern).status == ScanStatus::not_found,
            "short buffer should not match");
    require(!compile_pattern("4G", error) && !error.empty(), "invalid token accepted");
    require(!compile_pattern("   ", error), "empty pattern accepted");
}
void multiple_matches_are_rejected() {
    std::string error;
    const auto pattern = compile_pattern("AA ??", error);
    const std::vector<std::uint8_t> image{0xAA, 0x01, 0xAA, 0x02};
    const auto result = scan_unique(image, *pattern);
    require(result.status == ScanStatus::multiple_matches && result.matches == 2 && !result.error.empty(),
            "ambiguous pattern was accepted");
    const auto all_wildcards = compile_pattern("?? ??", error);
    require(all_wildcards && scan_unique(image, *all_wildcards).status == ScanStatus::multiple_matches,
            "all-wildcard ambiguity was accepted");
}
void rip_call_and_jump_math() {
    const std::vector<std::uint8_t> rip{0x48, 0x8B, 0x0D, 0x10, 0, 0, 0};
    require(resolve_relative(0x1000, rip, 3, 7) == 0x1017, "forward RIP failed");
    const std::vector<std::uint8_t> back{0xE8, 0xF0, 0xFF, 0xFF, 0xFF};
    require(resolve_relative_call(0x1000, back) == 0xFF5, "backward call failed");
    require(!resolve_relative_jump(0x1000, back), "call accepted as jump");
    require(!resolve_relative(0x1000, rip, 4, 7), "out-of-bounds displacement accepted");
    const std::vector<std::uint8_t> jump{0xE9, 0x10, 0, 0, 0};
    require(resolve_relative_jump(0x1000, jump) == 0x1015, "relative jump failed");
    require(!resolve_relative(UINT64_MAX - 2, rip, 3, 7), "address overflow accepted");
    require(!resolve_relative(1, back, 1, 5), "address underflow accepted");
}
void pe_section_parsing() {
    std::vector<std::uint8_t> bytes(0x2000);
    bytes[0] = 'M';
    bytes[1] = 'Z';
    put<std::uint32_t>(bytes, 0x3c, 0x80);
    put<std::uint32_t>(bytes, 0x80, 0x4550);
    put<std::uint16_t>(bytes, 0x84, 0x8664);
    put<std::uint16_t>(bytes, 0x86, 1);
    put<std::uint16_t>(bytes, 0x94, 0xF0);
    put<std::uint16_t>(bytes, 0x98, 0x20B);
    put<std::uint32_t>(bytes, 0x98 + 56, 0x2000);
    put<std::uint32_t>(bytes, 0x98 + 60, 0x400);
    put<std::uint32_t>(bytes, 0x98 + 112, 0x1080);
    put<std::uint32_t>(bytes, 0x98 + 116, 0x60);
    const std::size_t section = 0x80 + 24 + 0xF0;
    std::memcpy(bytes.data() + section, ".text", 5);
    put<std::uint32_t>(bytes, section + 8, 0x100);
    put<std::uint32_t>(bytes, section + 12, 0x1000);
    put<std::uint32_t>(bytes, section + 16, 0x100);
    put<std::uint32_t>(bytes, section + 20, 0x400);
    put<std::uint32_t>(bytes, section + 36, 0x60000020);
    bytes[0x1000] = 0xCC;
    put<std::uint32_t>(bytes, 0x1080 + 20, 1);
    put<std::uint32_t>(bytes, 0x1080 + 24, 1);
    put<std::uint32_t>(bytes, 0x1080 + 28, 0x10D0);
    put<std::uint32_t>(bytes, 0x1080 + 32, 0x10D4);
    put<std::uint32_t>(bytes, 0x1080 + 36, 0x10D8);
    put<std::uint32_t>(bytes, 0x10D0, 0x1000);
    put<std::uint32_t>(bytes, 0x10D4, 0x10E0);
    std::memcpy(bytes.data() + 0x10E0, "CreateInterface", 16);
    std::string error;
    const auto image = PeImage::from_mapped(bytes, error);
    require(image && image->machine() == 0x8664 && image->image_size() == 0x2000, "fake PE parse failed");
    require(image->section(".text") && image->section(".text")->rva == 0x1000, "section rva failed");
    require(image->at(0x1000, 1)[0] == 0xCC, "mapped section read failed");
    require(image->exports().size() == 1 && image->exports()[0].name == "CreateInterface" &&
                image->exports()[0].rva == 0x1000,
            "PE export parsing failed");
    auto raw = std::vector<std::uint8_t>(bytes.begin(), bytes.begin() + 0x500);
    std::copy_n(bytes.begin() + 0x1000, 0x100, raw.begin() + 0x400);
    const auto path =
        fs::temp_directory_path() /
        ("cs2-pe-test-" + std::to_string(std::chrono::steady_clock::now().time_since_epoch().count()) + ".dll");
    {
        std::ofstream file(path, std::ios::binary);
        file.write(reinterpret_cast<const char *>(raw.data()), raw.size());
    }
    const auto file_image = PeImage::from_file(path, error);
    require(file_image && file_image->exports().size() == 1, "raw PE file mapping failed");
    put<std::uint16_t>(raw, 0x86, 96);
    const auto bad_path =
        fs::temp_directory_path() /
        ("cs2-pe-bad-" + std::to_string(std::chrono::steady_clock::now().time_since_epoch().count()) + ".dll");
    {
        std::ofstream file(bad_path, std::ios::binary);
        file.write(reinterpret_cast<const char *>(raw.data()), raw.size());
    }
    require(!PeImage::from_file(bad_path, error), "truncated section table accepted");
    bytes[0] = 0;
    require(!PeImage::from_mapped(bytes, error), "bad DOS signature accepted");
}
void inheritance_and_duplicate_handling() {
    DumpDatabase db;
    Class base;
    base.scope = "client.dll";
    base.name = "Base";
    base.size = 64;
    base.fields.emplace("health", Field{"health", "int32", 4});
    require(db.insert_class(base), "base insertion failed");
    Class middle;
    middle.scope = "client.dll";
    middle.name = "Middle";
    middle.size = 96;
    middle.bases.push_back({"Base", "client.dll", 8});
    require(db.insert_class(middle), "middle insertion failed");
    Class child;
    child.scope = "client.dll";
    child.name = "Child";
    child.size = 128;
    child.bases.push_back({"Middle", "client.dll", 16});
    require(db.insert_class(child), "child insertion failed");
    require(db.inherited_field("client.dll", "Child", "health")->offset == 28, "inherited offset failed");
    require(!db.insert_class(base), "duplicate class silently overwritten");
    base.scope = "server.dll";
    require(db.insert_class(base), "same class name in another scope rejected");
    Class unknown;
    unknown.scope = "client.dll";
    unknown.name = "Unknown";
    unknown.size = 32;
    unknown.bases.push_back({"Base", "client.dll", std::nullopt});
    require(db.insert_class(unknown), "unknown-base test class insertion failed");
    require(!db.inherited_field("client.dll", "Unknown", "health"), "unknown base offset was guessed");
    db.classes.at("client.dll::Base").bases.push_back({"Child", "client.dll", 0});
    require(!db.inherited_field("client.dll", "Child", "missing"), "inheritance cycle did not terminate");
    DumpDatabase ambiguous;
    Class left = base;
    left.scope = "client.dll";
    left.type_scope = "left.dll";
    Class right = left;
    right.type_scope = "right.dll";
    require(ambiguous.insert_class(left) && ambiguous.insert_class(right), "scope-qualified duplicates rejected");
    require(!ambiguous.inherited_field("client.dll", "Base", "health"), "ambiguous inherited field was guessed");
}
void identifier_sanitization() {
    require(identifier("+attack", "cpp") == "_attack", "punctuation not sanitized");
    require(identifier("2nd", "rust") == "_2nd", "leading digit not sanitized");
    require(identifier("class", "cpp") == "class_", "C++ keyword not sanitized");
    require(identifier("pub", "rust") == "pub_", "Rust keyword not sanitized");
    require(identifier("struct", "zig") == "struct_", "Zig keyword not sanitized");
    require(identifier("type", "zig") == "type_" && identifier("i32", "zig") == "i32_", "Zig primitive not sanitized");
    require(identifier("namespace", "csharp") == "namespace_", "C# keyword not sanitized");
}
void json_serialization_and_generator_formatting() {
    DumpDatabase db;
    db.modules.emplace("client.dll", ModuleRecord{"client.dll", "test", "file_only", 0, 4096, 123, {}});
    Class value;
    value.scope = "client.dll";
    value.name = "C_Test";
    value.size = 64;
    value.fields.emplace("health", Field{"health", "int32", 4});
    require(db.insert_class(value), "fixture class insert failed");
    Enum first;
    first.scope = "client.dll";
    first.type_scope = "client.dll";
    first.name = "Mode";
    first.values.push_back({"Idle", 0});
    require(db.insert_enum(first), "first enum insert failed");
    Enum second = first;
    second.type_scope = "shared.dll";
    require(db.insert_enum(second), "same-name enum in another type scope rejected");
    db.offsets.emplace("client.dll::dwTest",
                       Offset{"dwTest", "client.dll", "signature", "test", "success", "signature_address", 32, {}});
    const auto directory =
        fs::temp_directory_path() /
        ("cs2-dumper-test-" + std::to_string(std::chrono::steady_clock::now().time_since_epoch().count()));
    std::string error;
    require(generate(db, directory, {"json", "cpp", "csharp", "rust", "zig"}, error), "generation failed");
    std::ifstream input(directory / "client_dll.json");
    const auto parsed = nlohmann::json::parse(input);
    require(parsed["classes"]["C_Test"]["fields"]["health"]["offset"] == 4, "numeric JSON field offset failed");
    require(parsed["classes"]["C_Test"]["fields"]["health"]["offset_hex"] == "0x4", "hex JSON field offset failed");
    require(parsed["enums"].size() == 2 && parsed["enums"].contains("Mode@client.dll") &&
                parsed["enums"].contains("Mode@shared.dll"),
            "same-name enums silently overwritten in JSON");
    auto read = [&](const char *extension) {
        std::ifstream file(directory / (std::string("client_dll.") + extension));
        return std::string(std::istreambuf_iterator<char>(file), std::istreambuf_iterator<char>());
    };
    require(read("hpp").find("inline constexpr std::ptrdiff_t health = 0x4;") != std::string::npos,
            "C++ generator field formatting failed");
    require(read("cs").find("public const ulong health = 0x4;") != std::string::npos,
            "C# generator field formatting failed");
    require(read("rs").find("pub const health: usize = 0x4;") != std::string::npos,
            "Rust generator field formatting failed");
    require(read("zig").find("pub const health: usize = 0x4;") != std::string::npos,
            "Zig generator field formatting failed");
    require(fs::exists(directory / "buttons.json") && fs::exists(directory / "interfaces.json") &&
                fs::exists(directory / "offsets.json") && fs::exists(directory / "info.json"),
            "required files missing");
    require(nlohmann::json::parse(std::ifstream(directory / "info.json"))["statistics"]["schema_fields"] == 1,
            "info statistics failed");
}
void duplicate_class_json_keys() {
    DumpDatabase db;
    db.modules.emplace("client.dll", ModuleRecord{"client.dll", "test", "file_only", 0, 4096, 123, {}});
    Class first;
    first.scope = "client.dll";
    first.type_scope = "client.dll";
    first.name = "Shared";
    first.size = 32;
    Class second = first;
    second.type_scope = "shared.dll";
    second.size = 64;
    require(db.insert_class(first) && db.insert_class(second), "scope-qualified class insertion failed");
    const auto directory =
        fs::temp_directory_path() /
        ("cs2-class-json-test-" + std::to_string(std::chrono::steady_clock::now().time_since_epoch().count()));
    std::string error;
    require(generate(db, directory, {"json"}, error), "duplicate class fixture generation failed");
    const auto parsed = nlohmann::json::parse(std::ifstream(directory / "client_dll.json"));
    require(parsed["classes"].size() == 2 && parsed["classes"].contains("Shared@client.dll") &&
                parsed["classes"].contains("Shared@shared.dll"),
            "same-name classes silently overwritten in JSON");
}
} // namespace
int main() {
    const std::pair<const char *, std::function<void()>> tests[] = {
        {"pattern_parser_and_wildcard_matching", pattern_parser_and_wildcard_matching},
        {"multiple_matches_are_rejected", multiple_matches_are_rejected},
        {"rip_call_and_jump_math", rip_call_and_jump_math},
        {"pe_section_parsing", pe_section_parsing},
        {"inheritance_and_duplicate_handling", inheritance_and_duplicate_handling},
        {"identifier_sanitization", identifier_sanitization},
        {"json_serialization_and_generator_formatting", json_serialization_and_generator_formatting},
        {"duplicate_class_json_keys", duplicate_class_json_keys},
    };
    int failures{};
    for (const auto &[name, test] : tests) {
        try {
            test();
            std::cout << "[PASS] " << name << '\n';
        } catch (const std::exception &e) {
            ++failures;
            std::cerr << "[FAIL] " << name << ": " << e.what() << '\n';
        }
    }
    return failures ? 1 : 0;
}
