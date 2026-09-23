#include "generators/generator.hpp"
#include <algorithm>
#include <cctype>
#include <chrono>
#include <fstream>
#include <iomanip>
#include <nlohmann/json.hpp>
#include <sstream>
#include <unordered_set>

namespace cs2 {
namespace {
using json = nlohmann::json;
std::string module_stem(std::string name) {
    std::replace(name.begin(), name.end(), '.', '_');
    return name;
}
std::string unique(std::string_view raw, std::string_view language, std::set<std::string> &used) {
    auto base = identifier(raw, language);
    auto name = base;
    for (std::size_t n = 2; !used.insert(name).second; ++n)
        name = base + "_" + std::to_string(n);
    return name;
}
json metadata_json(const std::vector<Metadata> &values) {
    json out = json::array();
    for (const auto &value : values)
        out.push_back({{"name", value.name}, {"value", value.value}});
    return out;
}
json module_json(const DumpDatabase &db, const ModuleRecord &module) {
    json out = {{"module", module.name},   {"available", module.status == "loaded" || module.status == "file_only"},
                {"status", module.status}, {"classes", json::object()},
                {"enums", json::object()}, {"exports", json::object()}};
    std::map<std::string, std::size_t> class_names;
    for (const auto &[key, klass] : db.classes) {
        (void)key;
        if (klass.scope == module.name)
            ++class_names[klass.name];
    }
    for (const auto &[key, klass] : db.classes) {
        (void)key;
        if (klass.scope != module.name)
            continue;
        json item = {
            {"size", klass.size},      {"alignment", klass.alignment}, {"type_scope", klass.type_scope},
            {"bases", json::array()},  {"fields", json::object()},     {"metadata", metadata_json(klass.metadata)},
            {"derived", json::array()}};
        for (const auto &base : klass.bases)
            item["bases"].push_back({{"name", base.name},
                                     {"scope", base.scope},
                                     {"offset", base.offset ? json(*base.offset) : json(nullptr)}});
        for (const auto &[other_key, other] : db.classes) {
            (void)other_key;
            for (const auto &base : other.bases)
                if (base.name == klass.name && (base.scope.empty() ? other.scope : base.scope) == klass.scope)
                    item["derived"].push_back(other.name);
        }
        for (const auto &[field_name, field] : klass.fields)
            item["fields"][field_name] = {{"offset", field.offset},
                                          {"offset_hex", hex(field.offset)},
                                          {"type", field.type},
                                          {"size", field.size ? json(field.size) : json(nullptr)},
                                          {"array_count", field.array_count ? json(field.array_count) : json(nullptr)},
                                          {"pointer", field.pointer},
                                          {"networked", field.networked},
                                          {"metadata", metadata_json(field.metadata)}};
        const auto output_name = class_names[klass.name] > 1 ? klass.name + "@" + klass.type_scope : klass.name;
        out["classes"][output_name] = std::move(item);
    }
    std::map<std::string, std::size_t> enum_names;
    for (const auto &[key, e] : db.enums) {
        (void)key;
        if (e.scope == module.name)
            ++enum_names[e.name];
    }
    for (const auto &[key, e] : db.enums) {
        (void)key;
        if (e.scope != module.name)
            continue;
        json values = json::object();
        for (const auto &v : e.values)
            values[v.name] = v.value;
        const auto output_name = enum_names[e.name] > 1 ? e.name + "@" + e.type_scope : e.name;
        out["enums"][output_name] = {
            {"size", e.size}, {"alignment", e.alignment}, {"type_scope", e.type_scope}, {"values", values}};
    }
    for (const auto &[name, rva] : module.exports)
        out["exports"][name] = rva;
    return out;
}
json interfaces_json(const DumpDatabase &db) {
    json out = json::object();
    for (const auto &[key, i] : db.interfaces) {
        (void)key;
        out[i.module][i.name] = {{"version", i.version},
                                 {"factory_rva", i.factory_rva},
                                 {"instance_rva", i.instance_rva ? json(*i.instance_rva) : json(nullptr)},
                                 {"vtable_rva", i.vtable_rva ? json(*i.vtable_rva) : json(nullptr)}};
    }
    return out;
}
json offsets_json(const DumpDatabase &db) {
    json out = json::object();
    for (const auto &[key, value] : db.offsets) {
        (void)key;
        out[value.module][value.name] = {{"status", value.status},
                                         {"kind", value.kind},
                                         {"relative_offset", value.status == "success" &&
                                                                     value.kind != "schema_pointer" &&
                                                                     value.kind != "button_list"
                                                                 ? json(value.relative)
                                                                 : json(nullptr)},
                                         {"method", value.method},
                                         {"signature", value.signature},
                                         {"detail", value.detail}};
    }
    return out;
}
json buttons_json(const DumpDatabase &db) {
    json out = json::object();
    for (const auto &[key, button] : db.buttons) {
        (void)key;
        out[button.name] = {{"module", button.module}, {"relative_offset", button.relative}, {"method", button.method}};
    }
    return out;
}
std::string language_header(std::string_view language) {
    if (language == "cpp")
        return "#pragma once\n#include <cstddef>\n#include <cstdint>\n\n";
    if (language == "rust")
        return "#![allow(non_snake_case, non_upper_case_globals)]\n\n";
    return {};
}
std::string open_scope(std::string_view language, const std::string &name, bool outer = false) {
    if (language == "cpp")
        return "namespace " + name + " {\n";
    if (language == "rust")
        return "pub mod " + name + " {\n";
    if (language == "zig")
        return "pub const " + name + " = struct {\n";
    if (language == "csharp")
        return outer ? "namespace CS2Dumper." + name + ";\n\n" : "public static class " + name + "\n{\n";
    return {};
}
std::string close_scope(std::string_view language) {
    return language == "zig" ? "};\n" : language == "csharp" ? "}\n" : "}\n";
}
std::string constant(std::string_view language, const std::string &name, std::uint64_t value,
                     std::string_view original = {}) {
    std::string s = "    ";
    if (language == "cpp")
        s += "inline constexpr std::ptrdiff_t " + name + " = " + hex(value) + ";";
    else if (language == "csharp")
        s += "public const ulong " + name + " = " + hex(value) + ";";
    else if (language == "rust")
        s += "pub const " + name + ": usize = " + hex(value) + ";";
    else if (language == "zig")
        s += "pub const " + name + ": usize = " + hex(value) + ";";
    if (!original.empty() && original != name)
        s += " // " + std::string(original);
    return s + "\n";
}
std::string render_module(const DumpDatabase &db, const ModuleRecord &module, std::string_view language) {
    std::string out = language_header(language);
    const auto root = identifier(module_stem(module.name), language);
    if (language == "cpp")
        out += "namespace cs2_dumper {\n";
    if (language == "csharp")
        out += open_scope(language, identifier(root, "csharp"), true);
    else
        out += open_scope(language, root);
    std::set<std::string> class_names;
    for (const auto &[key, klass] : db.classes) {
        (void)key;
        if (klass.scope != module.name)
            continue;
        const auto class_name = unique(klass.name, language, class_names);
        out += "\n" + open_scope(language, class_name);
        std::set<std::string> names;
        out += constant(language, unique("SIZE", language, names), klass.size);
        for (const auto &[name, field] : klass.fields) {
            auto id = unique(name, language, names);
            out += constant(language, id, field.offset, name);
        }
        out += close_scope(language);
    }
    for (const auto &[key, e] : db.enums) {
        (void)key;
        if (e.scope != module.name)
            continue;
        const auto enum_name = unique(e.name, language, class_names);
        out += "\n" + open_scope(language, enum_name);
        std::set<std::string> names;
        for (const auto &v : e.values) {
            const auto id = unique(v.name, language, names);
            if (language == "cpp")
                out += "    inline constexpr std::int64_t " + id + " = " + std::to_string(v.value) + ";\n";
            else if (language == "csharp")
                out += "    public const long " + id + " = " + std::to_string(v.value) + ";\n";
            else if (language == "rust")
                out += "    pub const " + id + ": i64 = " + std::to_string(v.value) + ";\n";
            else
                out += "    pub const " + id + ": i64 = " + std::to_string(v.value) + ";\n";
        }
        out += close_scope(language);
    }
    if (!module.exports.empty()) {
        out += "\n" + open_scope(language, unique("Exports", language, class_names));
        std::set<std::string> names;
        for (const auto &[name, rva] : module.exports)
            out += constant(language, unique(name, language, names), rva, name);
        out += close_scope(language);
    }
    if (language != "csharp")
        out += close_scope(language);
    if (language == "cpp")
        out += close_scope(language);
    return out;
}
std::string render_values(const DumpDatabase &db, std::string_view category, std::string_view language) {
    std::string out = language_header(language);
    if (language == "cpp")
        out += "namespace cs2_dumper {\n";
    if (language == "csharp")
        out += open_scope(language, std::string(category), true);
    else
        out += open_scope(language, std::string(category));
    std::map<std::string, std::vector<std::pair<std::string, std::uint64_t>>> grouped;
    if (category == "interfaces")
        for (const auto &[key, i] : db.interfaces) {
            (void)key;
            grouped[module_stem(i.module)].push_back({i.name, i.factory_rva});
        }
    if (category == "offsets")
        for (const auto &[key, i] : db.offsets) {
            (void)key;
            if (i.status == "success" && i.kind != "schema_pointer" && i.kind != "button_list")
                grouped[module_stem(i.module)].push_back({i.name, i.relative});
        }
    if (category == "buttons")
        for (const auto &[key, i] : db.buttons) {
            (void)key;
            grouped[module_stem(i.module)].push_back({i.name, i.relative});
        }
    for (const auto &[module, values] : grouped) {
        out += "\n" + open_scope(language, identifier(module, language));
        std::set<std::string> names;
        for (const auto &[name, value] : values)
            out += constant(language, unique(name, language, names), value, name);
        out += close_scope(language);
    }
    if (language != "csharp")
        out += close_scope(language);
    if (language == "cpp")
        out += close_scope(language);
    return out;
}
bool write(const std::filesystem::path &path, std::string_view content, std::string &error) {
    std::ofstream stream(path, std::ios::binary);
    if (!stream) {
        error = "cannot write " + path.string();
        return false;
    }
    stream.write(content.data(), static_cast<std::streamsize>(content.size()));
    if (!stream) {
        error = "write failed: " + path.string();
        return false;
    }
    return true;
}
std::string extension(std::string_view format) {
    if (format == "cpp")
        return "hpp";
    if (format == "csharp")
        return "cs";
    if (format == "rust")
        return "rs";
    if (format == "zig")
        return "zig";
    return "json";
}
} // namespace
std::string hex(std::uint64_t value) {
    std::ostringstream out;
    out << "0x" << std::uppercase << std::hex << value;
    return out.str();
}
std::string identifier(std::string_view source, std::string_view language) {
    static const std::unordered_set<std::string> cpp_words = {
        "class",   "struct",    "enum",      "namespace", "template", "typename", "operator", "delete",   "new",
        "default", "public",    "private",   "protected", "virtual",  "override", "final",    "static",   "const",
        "auto",    "int",       "float",     "double",    "void",     "this",     "return",   "if",       "else",
        "switch",  "case",      "for",       "while",     "do",       "break",    "continue", "true",     "false",
        "nullptr", "using",     "union",     "friend",    "char",     "short",    "long",     "unsigned", "signed",
        "bool",    "consteval", "constexpr", "concept",   "requires"};
    static const std::unordered_set<std::string> csharp_words = {
        "class", "struct", "enum",  "namespace", "public",   "private", "protected", "static",   "const",
        "void",  "int",    "long",  "ulong",     "string",   "object",  "base",      "this",     "new",
        "ref",   "out",    "in",    "return",    "if",       "else",    "for",       "while",    "true",
        "false", "null",   "using", "event",     "delegate", "params",  "default",   "operator", "global"};
    static const std::unordered_set<std::string> rust_words = {
        "as",     "async", "await", "break", "const",  "continue", "crate", "dyn",  "else",   "enum",
        "extern", "false", "fn",    "for",   "if",     "impl",     "in",    "let",  "loop",   "match",
        "mod",    "move",  "mut",   "pub",   "ref",    "return",   "self",  "Self", "static", "struct",
        "super",  "trait", "true",  "type",  "unsafe", "use",      "where", "while"};
    static const std::unordered_set<std::string> zig_words = {
        "align",     "allowzero", "and",         "anyframe",       "anytype",     "asm",          "async",
        "await",     "break",     "catch",       "comptime",       "const",       "continue",     "defer",
        "else",      "enum",      "errdefer",    "error",          "export",      "extern",       "false",
        "fn",        "for",       "if",          "inline",         "noalias",     "nosuspend",    "null",
        "opaque",    "or",        "orelse",      "packed",         "pub",         "resume",       "return",
        "struct",    "suspend",   "switch",      "test",           "threadlocal", "true",         "try",
        "undefined", "union",     "unreachable", "usingnamespace", "var",         "volatile",     "while",
        "type",      "void",      "bool",        "noreturn",       "anyerror",    "comptime_int", "comptime_float",
        "usize",     "isize",     "c_char",      "c_short",        "c_int",       "c_long",       "c_longlong",
        "c_ushort",  "c_uint",    "c_ulong",     "c_ulonglong",    "c_float",     "c_double",     "c_longdouble"};
    std::string result;
    for (unsigned char c : source)
        result.push_back(std::isalnum(c) || c == '_' ? static_cast<char>(c) : '_');
    if (result.empty())
        result = "unnamed";
    if (std::isdigit(static_cast<unsigned char>(result[0])))
        result.insert(result.begin(), '_');
    const auto &words = language == "rust"     ? rust_words
                        : language == "zig"    ? zig_words
                        : language == "csharp" ? csharp_words
                                               : cpp_words;
    const bool zig_number_type =
        language == "zig" && result.size() > 1 && (result[0] == 'u' || result[0] == 'i' || result[0] == 'f') &&
        std::all_of(result.begin() + 1, result.end(), [](unsigned char c) { return std::isdigit(c); });
    if (words.contains(result) || zig_number_type || result.rfind("__", 0) == 0 ||
        (result.size() > 1 && result[0] == '_' && std::isupper(static_cast<unsigned char>(result[1]))))
        result += '_';
    return result;
}
bool generate(const DumpDatabase &db, const std::filesystem::path &directory, const std::set<std::string> &formats,
              std::string &error) {
    std::error_code ec;
    std::filesystem::create_directories(directory, ec);
    if (ec) {
        error = "cannot create output directory: " + ec.message();
        return false;
    }
    for (const auto &[module_name, module] : db.modules) {
        const auto stem = module_stem(module_name);
        for (const auto &format : formats) {
            const auto path = directory / (stem + "." + extension(format));
            const auto content =
                format == "json" ? module_json(db, module).dump(2) + "\n" : render_module(db, module, format);
            if (!write(path, content, error))
                return false;
        }
    }
    for (const auto category : {"interfaces", "offsets", "buttons"}) {
        for (const auto &format : formats) {
            const auto path = directory / (std::string(category) + "." + extension(format));
            const auto content = format == "json" ? (std::string(category) == "interfaces" ? interfaces_json(db)
                                                     : std::string(category) == "offsets"  ? offsets_json(db)
                                                                                           : buttons_json(db))
                                                            .dump(2) +
                                                        "\n"
                                                  : render_values(db, category, format);
            if (!write(path, content, error))
                return false;
        }
    }
    const auto now = std::chrono::system_clock::now();
    const auto time = std::chrono::system_clock::to_time_t(now);
    std::tm utc{};
#ifdef _WIN32
    gmtime_s(&utc, &time);
#else
    gmtime_r(&time, &utc);
#endif
    std::ostringstream timestamp;
    timestamp << std::put_time(&utc, "%Y-%m-%dT%H:%M:%SZ");
    json info = {{"tool", "cs2-dumper"},
                 {"version", "0.1.0"},
                 {"game", "Counter-Strike 2"},
                 {"dump_timestamp", timestamp.str()},
                 {"platform", "Windows"},
                 {"architecture", "x86_64"},
                 {"steam_build_id", db.steam_build_id.empty() ? json(nullptr) : json(db.steam_build_id)},
                 {"game_build", db.game_build.empty() ? json(nullptr) : json(db.game_build)},
                 {"modules", json::object()},
                 {"statistics", json::object()},
                 {"generator_languages", json::array()},
                 {"issues", json::array()}};
    for (const auto &[name, module] : db.modules)
        info["modules"][name] = {{"status", module.status},
                                 {"image_size", module.image_size},
                                 {"pe_timestamp", module.timestamp},
                                 {"path", module.path}};
    std::size_t successes{}, failures{};
    for (const auto &[key, value] : db.offsets) {
        (void)key;
        value.status == "success" ? ++successes : ++failures;
    }
    std::size_t vtables{};
    for (const auto &[key, value] : db.interfaces) {
        (void)key;
        if (value.vtable_rva)
            ++vtables;
    }
    info["statistics"] = {{"schema_classes", db.classes.size()},
                          {"schema_fields", db.field_count()},
                          {"schema_enums", db.enums.size()},
                          {"interfaces", db.interfaces.size()},
                          {"validated_interface_vtables", vtables},
                          {"buttons", db.buttons.size()},
                          {"signature_successes", successes},
                          {"signature_failures", failures},
                          {"warnings", db.issues.size()}};
    for (const auto &format : formats)
        info["generator_languages"].push_back(format);
    for (const auto &issue : db.issues)
        info["issues"].push_back({{"level", issue.level}, {"context", issue.context}, {"message", issue.message}});
    return write(directory / "info.json", info.dump(2) + "\n", error);
}
} // namespace cs2
