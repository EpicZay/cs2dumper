#pragma once
#include "core/pe.hpp"
#include "core/process.hpp"
#include "database/database.hpp"
#include <map>
#include <nlohmann/json.hpp>
#include <optional>

namespace cs2 {
struct ModuleImage {
    LoadedModule loaded;
    PeImage pe;
};
using ModuleImages = std::map<std::string, ModuleImage>;
struct CollectionOptions {
    bool schema{true}, interfaces{true}, offsets{true}, buttons{true}, signatures{true}, verbose{};
};
struct CollectionResult {
    std::optional<std::uint64_t> schema_address, button_list_address;
};
void collect_exports(const ModuleImages &images, DumpDatabase &db);
CollectionResult collect_signatures(const ModuleImages &images, const MemoryReader *memory,
                                    const nlohmann::json &config, DumpDatabase &db, const CollectionOptions &options);
void collect_interfaces(const ModuleImages &images, const MemoryReader &memory, DumpDatabase &db);
void collect_schema(const MemoryReader &memory, std::uint64_t address, const nlohmann::json &layout, DumpDatabase &db);
void collect_buttons(const MemoryReader &memory, std::uint64_t address, const nlohmann::json &layout, DumpDatabase &db);
} // namespace cs2
