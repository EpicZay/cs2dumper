#include "core/pe.hpp"
#include "core/process.hpp"
#include "database/database.hpp"
#include "generators/generator.hpp"
#include "source2/collect.hpp"
#include <algorithm>
#include <cctype>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <nlohmann/json.hpp>
#include <set>

namespace fs = std::filesystem;
using namespace cs2;

namespace {
struct Options {
    fs::path output{"output"}, game_dir, config_dir{"config"};
    std::set<std::string> formats{"json", "cpp", "csharp", "rust", "zig"};
    std::string module;
    std::optional<std::uint32_t> pid;
    CollectionOptions collection;
    bool validate{}, offline{};
};
void help() {
    std::cout << "cs2-dumper 0.1.0 (read-only)\n"
              << "  --output DIR             Output directory\n"
              << "  --game-dir DIR           CS2 game root or game/bin/win64\n"
              << "  --config-dir DIR         Configuration directory\n"
              << "  --pid ID                 Attach to a specific cs2.exe process\n"
              << "  --offline                Parse local files without attaching to CS2\n"
              << "  --format all|json|cpp|csharp|rust|zig (repeatable)\n"
              << "  --module NAME            Restrict to one DLL\n"
              << "  --schema-only | --interfaces-only | --offsets-only\n"
              << "  --no-signatures --verbose --validate --help\n";
}
bool parse(int argc, char **argv, Options &o, std::string &error) {
    bool format_seen{};
    for (int i = 1; i < argc; ++i) {
        const std::string arg = argv[i];
        const auto value = [&]() -> std::optional<std::string> {
            if (i + 1 >= argc) {
                error = "missing value for " + arg;
                return std::nullopt;
            }
            return std::string(argv[++i]);
        };
        if (arg == "--help") {
            help();
            return false;
        }
        if (arg == "--output") {
            if (auto v = value())
                o.output = *v;
            else
                return false;
        } else if (arg == "--game-dir") {
            if (auto v = value())
                o.game_dir = *v;
            else
                return false;
        } else if (arg == "--config-dir") {
            if (auto v = value())
                o.config_dir = *v;
            else
                return false;
        } else if (arg == "--module") {
            if (auto v = value())
                o.module = *v;
            else
                return false;
        } else if (arg == "--pid") {
            if (auto v = value()) {
                try {
                    o.pid = static_cast<std::uint32_t>(std::stoul(*v));
                } catch (...) {
                    error = "invalid process ID";
                    return false;
                }
            } else
                return false;
        } else if (arg == "--format") {
            auto v = value();
            if (!v)
                return false;
            if (*v != "all" && *v != "json" && *v != "cpp" && *v != "csharp" && *v != "rust" && *v != "zig") {
                error = "unknown format: " + *v;
                return false;
            }
            if (!format_seen) {
                o.formats.clear();
                format_seen = true;
            }
            if (*v == "all")
                o.formats = {"json", "cpp", "csharp", "rust", "zig"};
            else
                o.formats.insert(*v);
        } else if (arg == "--schema-only") {
            o.collection = {};
            o.collection.interfaces = false;
            o.collection.offsets = false;
            o.collection.buttons = false;
        } else if (arg == "--interfaces-only") {
            o.collection = {};
            o.collection.schema = false;
            o.collection.offsets = false;
            o.collection.buttons = false;
        } else if (arg == "--offsets-only") {
            o.collection = {};
            o.collection.schema = false;
            o.collection.interfaces = false;
            o.collection.buttons = false;
        } else if (arg == "--no-signatures")
            o.collection.signatures = false;
        else if (arg == "--offline")
            o.offline = true;
        else if (arg == "--verbose")
            o.collection.verbose = true;
        else if (arg == "--validate")
            o.validate = true;
        else {
            error = "unknown argument: " + arg;
            return false;
        }
    }
    return true;
}
std::optional<nlohmann::json> read_json(const fs::path &path, std::string &error) {
    std::ifstream input(path);
    if (!input) {
        error = "cannot open " + path.string();
        return std::nullopt;
    }
    try {
        return nlohmann::json::parse(input);
    } catch (const std::exception &e) {
        error = "invalid JSON in " + path.string() + ": " + e.what();
        return std::nullopt;
    }
}
fs::path module_directory(fs::path input) {
    if (input.empty())
        return {};
    if (fs::exists(input / "game" / "bin" / "win64"))
        return input / "game" / "bin" / "win64";
    return input;
}
fs::path module_file(const fs::path &directory, const std::string &name) {
    if (fs::exists(directory / name))
        return directory / name;
    const auto game = directory.parent_path().parent_path();
    const auto csgo = game / "csgo" / "bin" / "win64" / name;
    if (fs::exists(csgo))
        return csgo;
    return directory / name;
}
std::string lower(std::string value) {
    std::transform(value.begin(), value.end(), value.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return value;
}
std::string steam_build_id(fs::path from) {
    while (!from.empty()) {
        if (lower(from.filename().string()) == "steamapps") {
            std::ifstream manifest(from / "appmanifest_730.acf");
            std::string line;
            while (std::getline(manifest, line)) {
                if (line.find("\"buildid\"") == std::string::npos)
                    continue;
                const auto first = line.find('"', line.find("buildid") + 8);
                const auto second = first == std::string::npos ? first : line.find('"', first + 1);
                if (first != std::string::npos && second != std::string::npos)
                    return line.substr(first + 1, second - first - 1);
            }
            break;
        }
        const auto parent = from.parent_path();
        if (parent == from)
            break;
        from = parent;
    }
    return {};
}
} // namespace

int main(int argc, char **argv) {
    Options options;
    std::string error;
    if (!parse(argc, argv, options, error)) {
        if (error.empty())
            return 0;
        std::cerr << "[ERROR] " << error << '\n';
        return 2;
    }
    const auto modules_config = read_json(options.config_dir / "modules.json", error);
    if (!modules_config || !modules_config->is_array()) {
        std::cerr << "[ERROR] " << error << '\n';
        return 2;
    }
    const auto signatures = read_json(options.config_dir / "signatures.json", error);
    if (!signatures) {
        std::cerr << "[ERROR] " << error << '\n';
        return 2;
    }
    const auto layouts = read_json(options.config_dir / "layouts.json", error);
    if (!layouts) {
        std::cerr << "[ERROR] " << error << '\n';
        return 2;
    }

    DumpDatabase db;
    ProcessReader process;
    const auto pid = options.offline ? std::optional<std::uint32_t>{}
                     : options.pid   ? options.pid
                                     : ProcessReader::find_pid(L"cs2.exe");
    std::vector<LoadedModule> loaded;
    if (pid) {
        if (process.attach(*pid, error)) {
            loaded = process.modules(error);
            std::cout << "[INFO] Attached read-only to cs2.exe (PID " << *pid << "), " << loaded.size() << " modules\n";
        } else
            db.issues.push_back({"WARN", "process", error});
    }
    if (options.game_dir.empty()) {
        for (const auto &m : loaded)
            if (m.name == "cs2.exe") {
                options.game_dir = m.path.parent_path();
                break;
            }
    }
    options.game_dir = module_directory(options.game_dir);
    if (options.game_dir.empty()) {
        std::cerr << "[ERROR] CS2 is not running; supply --game-dir for offline PE/signature export\n";
        return 2;
    }
    db.steam_build_id = steam_build_id(options.game_dir);
    ModuleImages images;
    for (const auto &item : *modules_config) {
        if (!item.is_string())
            continue;
        const auto name = lower(item.get<std::string>());
        const auto active =
            std::find_if(loaded.begin(), loaded.end(), [&](const LoadedModule &m) { return m.name == name; });
        fs::path path = active == loaded.end() ? module_file(options.game_dir, name) : active->path;
        ModuleRecord record{name,
                            path.string(),
                            "unavailable",
                            active == loaded.end() ? 0 : active->base,
                            active == loaded.end() ? 0 : active->size,
                            0,
                            {}};
        if (fs::exists(path)) {
            if (auto pe = PeImage::from_file(path, error)) {
                record.status = active == loaded.end() ? "file_only" : "loaded";
                record.image_size = pe->image_size();
                record.timestamp = pe->timestamp();
                images.emplace(name, ModuleImage{{name, path, record.base, record.image_size}, std::move(*pe)});
                if (options.collection.verbose)
                    std::cout << "[DEBUG] " << name << " " << record.status << "\n";
            } else {
                record.status = "parse_error";
                db.issues.push_back({"WARN", name, error});
            }
        } else
            db.issues.push_back({"WARN", name, "module file unavailable"});
        db.modules.emplace(name, std::move(record));
    }
    const auto game_root = lower(options.game_dir.parent_path().parent_path().string());
    for (const auto &active : loaded) {
        if (db.modules.contains(active.name) || active.name.size() < 5 ||
            active.name.substr(active.name.size() - 4) != ".dll" ||
            lower(active.path.string()).rfind(game_root, 0) != 0)
            continue;
        if (auto pe = PeImage::from_file(active.path, error)) {
            if (std::none_of(pe->exports().begin(), pe->exports().end(),
                             [](const auto &e) { return e.name == "CreateInterface" && !e.forwarded; }))
                continue;
            db.modules.emplace(
                active.name,
                ModuleRecord{
                    active.name, active.path.string(), "loaded", active.base, pe->image_size(), pe->timestamp(), {}});
            images.emplace(active.name, ModuleImage{active, std::move(*pe)});
        }
    }
    collect_exports(images, db);
    if (options.collection.interfaces && process.attached())
        collect_interfaces(images, process, db);
    const auto discovered =
        collect_signatures(images, process.attached() ? &process : nullptr, *signatures, db, options.collection);
    if (process.attached()) {
        const auto build = db.offsets.find(qualified("engine2.dll", "dwBuildNumber"));
        const auto module = db.modules.find("engine2.dll");
        if (build != db.offsets.end() && build->second.status == "success" && module != db.modules.end() &&
            module->second.base && build->second.relative < module->second.image_size) {
            const auto value = process.value<std::uint32_t>(module->second.base + build->second.relative);
            if (value && *value > 0 && *value < 10000000)
                db.game_build = *value;
            else
                db.issues.push_back({"WARN", "game_build", "build number unreadable or implausible"});
        }
    }
    if (options.collection.verbose)
        for (const auto &[key, result] : db.offsets)
            std::cout << "[TRACE] " << key << " " << result.status << '\n';
    auto schema_address = discovered.schema_address;
    if (!schema_address && process.attached()) {
        for (const auto &[key, iface] : db.interfaces) {
            (void)key;
            if (iface.module == "schemasystem.dll" && iface.name.rfind("SchemaSystem_", 0) == 0 && iface.instance_rva) {
                const auto module = db.modules.find(iface.module);
                if (module != db.modules.end()) {
                    schema_address = module->second.base + *iface.instance_rva;
                    break;
                }
            }
        }
    }
    if (options.collection.schema && process.attached()) {
        if (schema_address) {
            std::cout << "[INFO] Walking SchemaSystem type scopes\n";
            collect_schema(process, *schema_address, *layouts, db);
        } else
            db.issues.push_back({"ERROR", "SchemaSystem", "no validated schema pointer discovered"});
    } else if (options.collection.schema)
        db.issues.push_back({"WARN", "SchemaSystem", "live process unavailable; schema collection skipped"});
    {
        ModuleImages extra_images;
        std::set<std::string> owners;
        for (const auto &[key, klass] : db.classes) {
            (void)key;
            owners.insert(lower(klass.scope));
        }
        for (const auto &[key, e] : db.enums) {
            (void)key;
            owners.insert(lower(e.scope));
        }
        for (const auto &name : owners) {
            if (db.modules.contains(name))
                continue;
            const auto active =
                std::find_if(loaded.begin(), loaded.end(), [&](const LoadedModule &m) { return m.name == name; });
            const fs::path path = active == loaded.end() ? module_file(options.game_dir, name) : active->path;
            ModuleRecord record{name,
                                path.string(),
                                "unavailable",
                                active == loaded.end() ? 0 : active->base,
                                active == loaded.end() ? 0 : active->size,
                                0,
                                {}};
            if (fs::exists(path)) {
                if (auto pe = PeImage::from_file(path, error)) {
                    record.status = active == loaded.end() ? "file_only" : "loaded";
                    record.image_size = pe->image_size();
                    record.timestamp = pe->timestamp();
                    extra_images.emplace(name,
                                         ModuleImage{{name, path, record.base, record.image_size}, std::move(*pe)});
                } else {
                    record.status = "parse_error";
                    db.issues.push_back({"WARN", name, error});
                }
            } else {
                record.status = "schema_only";
                record.path.clear();
            }
            db.modules.emplace(name, std::move(record));
        }
        collect_exports(extra_images, db);
        if (options.collection.interfaces && process.attached())
            collect_interfaces(extra_images, process, db);
    }
    if (!options.module.empty() && !db.modules.contains(lower(options.module))) {
        std::cerr << "[ERROR] module unavailable: " << options.module << '\n';
        return 2;
    }
    if (options.collection.buttons && process.attached()) {
        if (discovered.button_list_address)
            collect_buttons(process, *discovered.button_list_address, *layouts, db);
        else if (options.collection.signatures)
            db.issues.push_back({"WARN", "buttons", "no button-list signature configured or resolved"});
    }
    db.validate();
    if (!options.module.empty()) {
        const auto only = lower(options.module);
        std::erase_if(db.modules, [&](const auto &item) { return item.first != only; });
        std::erase_if(db.classes, [&](const auto &item) { return lower(item.second.scope) != only; });
        std::erase_if(db.enums, [&](const auto &item) { return lower(item.second.scope) != only; });
        std::erase_if(db.interfaces, [&](const auto &item) { return lower(item.second.module) != only; });
        std::erase_if(db.offsets, [&](const auto &item) { return lower(item.second.module) != only; });
        std::erase_if(db.buttons, [&](const auto &item) { return lower(item.second.module) != only; });
    }
    if (!generate(db, options.output, options.formats, error)) {
        std::cerr << "[ERROR] " << error << '\n';
        return 1;
    }
    std::size_t successes{}, failures{};
    for (const auto &[key, offset] : db.offsets) {
        (void)key;
        offset.status == "success" ? ++successes : ++failures;
    }
    for (const auto &issue : db.issues) {
        if (options.collection.verbose || issue.level == "ERROR" || options.validate)
            std::cout << '[' << issue.level << "] " << issue.context << ": " << issue.message << '\n';
    }
    std::cout << "[INFO] " << db.classes.size() << " classes, " << db.field_count() << " fields, " << db.enums.size()
              << " enums, " << db.interfaces.size() << " interfaces, " << db.buttons.size() << " buttons\n"
              << "[INFO] Signatures: " << successes << " successful, " << failures << " failed; " << db.issues.size()
              << " issues\n"
              << "[INFO] Generated files in " << fs::absolute(options.output).string() << '\n';
    return 0;
}
