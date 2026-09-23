#include "source2/collect.hpp"
#include "core/pattern.hpp"
#include <algorithm>
#include <array>
#include <cctype>
#include <cstring>
#include <set>
#include <unordered_set>

namespace cs2 {
namespace {
template <class T> std::optional<T> at(const MemoryReader &mem, std::uint64_t address, std::size_t offset) {
    if (address > UINT64_MAX - offset)
        return std::nullopt;
    return mem.value<T>(address + offset);
}
std::optional<std::string> ptr_string(const MemoryReader &mem, std::uint64_t address, std::size_t offset,
                                      std::size_t max = 128) {
    const auto pointer = at<std::uint64_t>(mem, address, offset);
    return pointer ? mem.string(*pointer, max) : std::nullopt;
}
std::uint32_t offset(const nlohmann::json &layout, const char *group, const char *name) {
    return layout.at(group).at(name).get<std::uint32_t>();
}
std::optional<std::uint64_t> factory_instance(const MemoryReader &mem, std::uint64_t function) {
    std::array<std::uint8_t, 32> code{};
    if (!mem.read(function, code))
        return std::nullopt;
    std::size_t start = 0;
    if (code[0] == 0xE9) {
        const auto jump = resolve_relative_jump(function, code);
        if (!jump || !mem.read(*jump, code))
            return std::nullopt;
        function = *jump;
    }
    if (code[0] == 0xF3 && code[1] == 0x0F && code[2] == 0x1E && code[3] == 0xFA)
        start = 4;
    for (std::size_t i = start; i + 7 < code.size() && i < start + 12; ++i) {
        if (code[i] != 0x48 || (code[i + 1] != 0x8B && code[i + 1] != 0x8D) || code[i + 2] != 0x05)
            continue;
        if (code[i + 7] != 0xC3 && (i + 8 >= code.size() || code[i + 8] != 0xC3))
            continue;
        const auto target = resolve_relative(function + i, std::span<const std::uint8_t>(code).subspan(i), 3, 7);
        if (!target)
            return std::nullopt;
        if (code[i + 1] == 0x8D)
            return target;
        return mem.value<std::uint64_t>(*target);
    }
    return std::nullopt;
}
bool in_module(const ModuleImage &m, std::uint64_t address) {
    return address >= m.loaded.base && address - m.loaded.base < m.pe.image_size();
}
std::string status_name(ScanStatus status) {
    switch (status) {
    case ScanStatus::success:
        return "success";
    case ScanStatus::not_found:
        return "not_found";
    case ScanStatus::multiple_matches:
        return "multiple_matches";
    case ScanStatus::invalid_pattern:
        return "invalid_pattern";
    case ScanStatus::invalid_module:
        return "invalid_module";
    case ScanStatus::invalid_instruction:
        return "invalid_instruction";
    }
    return "unknown";
}
std::vector<Metadata> read_metadata(const MemoryReader &mem, std::uint64_t pointer, std::uint32_t count,
                                    const nlohmann::json &layout) {
    std::vector<Metadata> out;
    if (!pointer || count > 128)
        return out;
    const auto stride = offset(layout, "metadata", "stride");
    for (std::uint32_t i = 0; i < count; ++i) {
        const auto address = pointer + static_cast<std::uint64_t>(i) * stride;
        const auto name = ptr_string(mem, address, offset(layout, "metadata", "name"));
        if (!name || name->empty())
            continue;
        Metadata item{*name, {}};
        const auto raw = at<std::uint64_t>(mem, address, offset(layout, "metadata", "value"));
        if (raw && *raw && (*name == "MNetworkChangeCallback" || *name == "MNetworkVarNames")) {
            if (*name == "MNetworkChangeCallback") {
                if (const auto p = mem.value<std::uint64_t>(*raw))
                    item.value = mem.string(*p).value_or("");
            } else if (const auto p = mem.value<std::uint64_t>(*raw)) {
                if (const auto q = mem.value<std::uint64_t>(*raw + 8)) {
                    const auto n = mem.string(*p).value_or("");
                    const auto t = mem.string(*q).value_or("");
                    item.value = n.empty() ? "" : n + ":" + t;
                }
            }
        }
        out.push_back(std::move(item));
    }
    return out;
}
std::uint32_t built_in_size(std::string_view type) {
    if (type == "bool" || type == "char" || type == "int8" || type == "uint8")
        return 1;
    if (type == "int16" || type == "uint16")
        return 2;
    if (type == "int32" || type == "uint32" || type == "float32" || type == "float")
        return 4;
    if (type == "int64" || type == "uint64" || type == "float64" || type == "double")
        return 8;
    return 0;
}
std::vector<std::uint64_t> hash_bindings(const MemoryReader &mem, std::uint64_t hash, const nlohmann::json &layout,
                                         DumpDatabase &db, const std::string &scope) {
    std::vector<std::uint64_t> result;
    const auto bucket_start = offset(layout, "hash", "bucket_start");
    const auto bucket_count = offset(layout, "hash", "bucket_count");
    const auto bucket_stride = offset(layout, "hash", "bucket_stride");
    if (bucket_count > 4096 || bucket_stride < 16)
        return result;
    std::unordered_set<std::uint64_t> seen;
    for (std::uint32_t i = 0; i < bucket_count; ++i) {
        const auto bucket = hash + bucket_start + static_cast<std::uint64_t>(i) * bucket_stride;
        for (const auto head_offset : {offset(layout, "hash", "first"), offset(layout, "hash", "uncommitted")}) {
            auto node = at<std::uint64_t>(mem, bucket, head_offset).value_or(0);
            std::size_t steps{};
            while (node && steps++ < 10000 && result.size() < 100000) {
                if (!seen.insert(node).second)
                    break;
                const auto data = at<std::uint64_t>(mem, node, offset(layout, "hash", "node_data"));
                if (!data)
                    break;
                if (*data)
                    result.push_back(*data);
                node = at<std::uint64_t>(mem, node, offset(layout, "hash", "node_next")).value_or(0);
            }
            if (steps >= 10000)
                db.issues.push_back({"WARN", scope, "hash bucket traversal limit reached"});
        }
    }
    auto free_node = at<std::uint64_t>(mem, hash, offset(layout, "hash", "free_head")).value_or(0);
    const auto peak = at<std::int32_t>(mem, hash, offset(layout, "hash", "peak_allocated")).value_or(0);
    std::unordered_set<std::uint64_t> free_seen;
    for (std::int32_t i = 0; free_node && i < std::min(peak, 100000) && free_seen.insert(free_node).second; ++i) {
        const auto data = at<std::uint64_t>(mem, free_node, offset(layout, "hash", "free_data"));
        if (!data)
            break;
        if (*data)
            result.push_back(*data);
        free_node = at<std::uint64_t>(mem, free_node, offset(layout, "hash", "free_next")).value_or(0);
    }
    std::sort(result.begin(), result.end());
    result.erase(std::unique(result.begin(), result.end()), result.end());
    return result;
}
} // namespace

void collect_exports(const ModuleImages &images, DumpDatabase &db) {
    for (const auto &[name, image] : images) {
        auto it = db.modules.find(name);
        if (it == db.modules.end())
            continue;
        for (const auto &e : image.pe.exports())
            if (!e.forwarded)
                it->second.exports.emplace(e.name, e.rva);
    }
}

CollectionResult collect_signatures(const ModuleImages &images, const MemoryReader *memory,
                                    const nlohmann::json &config, DumpDatabase &db, const CollectionOptions &options) {
    CollectionResult output;
    if (!options.signatures)
        return output;
    if (!config.is_array()) {
        db.issues.push_back({"ERROR", "config/signatures.json", "expected JSON array"});
        return output;
    }
    for (const auto &entry : config) {
        try {
            const auto module = entry.at("module").get<std::string>();
            const auto name = entry.at("name").get<std::string>();
            const auto kind = entry.value("kind", std::string("signature_address"));
            if ((kind == "schema_pointer" && !options.schema) || (kind == "button_list" && !options.buttons) ||
                (kind != "schema_pointer" && kind != "button_list" && !options.offsets))
                continue;
            Offset record{name, module, "signature", name, "not_found", kind, 0, {}};
            const auto key = qualified(module, name);
            if (db.offsets.contains(key)) {
                db.issues.push_back({"WARN", key, "duplicate signature name"});
                continue;
            }
            if (!memory && (kind == "schema_pointer" || kind == "button_list")) {
                record.status = "requires_live_process";
                db.offsets.emplace(key, std::move(record));
                continue;
            }
            const auto image = images.find(module);
            if (image == images.end()) {
                record.status = "invalid_module";
                db.offsets.emplace(key, record);
                continue;
            }
            std::string error;
            const auto pattern = compile_pattern(entry.at("pattern").get<std::string>(), error);
            if (!pattern) {
                record.status = "invalid_pattern";
                record.detail = error;
                db.offsets.emplace(key, record);
                continue;
            }
            const auto section_name = entry.value("section", std::string(".text"));
            const auto section = image->second.pe.section(section_name);
            if (!section) {
                record.status = "invalid_module";
                record.detail = "section absent: " + section_name;
                db.offsets.emplace(key, record);
                continue;
            }
            const auto size =
                std::min<std::uint32_t>(section->virtual_size, image->second.pe.image_size() - section->rva);
            const auto bytes = image->second.pe.at(section->rva, size);
            auto match = scan_unique(bytes, *pattern);
            if (match.status != ScanStatus::success) {
                record.status = status_name(match.status);
                record.detail = match.error;
                db.offsets.emplace(key, record);
                continue;
            }
            const auto match_rva = static_cast<std::uint64_t>(section->rva) + match.offset;
            std::uint64_t address = image->second.loaded.base + match_rva;
            const auto resolver = entry.value("resolver", nlohmann::json::object());
            const auto type = resolver.value("type", std::string("none"));
            if (type == "rip") {
                const auto displacement = resolver.at("displacement_offset").get<std::size_t>();
                const auto length = resolver.at("instruction_length").get<std::size_t>();
                const auto resolved = resolve_relative(address, bytes.subspan(match.offset), displacement, length);
                if (!resolved)
                    record.status = "invalid_instruction";
                else
                    address = *resolved;
            } else if (type == "call" || type == "jump") {
                const auto code = bytes.subspan(match.offset);
                const auto resolved =
                    type == "call" ? resolve_relative_call(address, code) : resolve_relative_jump(address, code);
                if (!resolved)
                    record.status = "invalid_instruction";
                else
                    address = *resolved;
            } else if (type == "immediate") {
                const auto imm_offset = resolver.at("offset").get<std::size_t>();
                const auto width = resolver.at("width").get<std::size_t>();
                if (match.offset + imm_offset > bytes.size() || width > bytes.size() - match.offset - imm_offset ||
                    (width != 1 && width != 2 && width != 4 && width != 8))
                    record.status = "invalid_instruction";
                else {
                    address = 0;
                    std::memcpy(&address, bytes.data() + match.offset + imm_offset, width);
                }
            } else if (type != "none")
                record.status = "invalid_instruction";
            if (record.status == "invalid_instruction") {
                db.offsets.emplace(key, record);
                continue;
            }
            for (std::size_t i = 0; i < entry.value("dereference", std::size_t{0}); ++i) {
                if (!memory || !(address = memory->value<std::uint64_t>(address).value_or(0))) {
                    record.status = "invalid_instruction";
                    record.detail = "pointer dereference failed";
                    break;
                }
            }
            if (record.status == "invalid_instruction") {
                db.offsets.emplace(key, record);
                continue;
            }
            if (kind == "schema_pointer") {
                if (in_module(image->second, address)) {
                    output.schema_address = address;
                    record.relative = address - image->second.loaded.base;
                    record.status = "success";
                } else {
                    record.status = "invalid_module";
                    record.detail = "schema target outside source module";
                }
            } else if (kind == "button_list") {
                output.button_list_address = address;
                record.status = "success";
            } else if (kind == "member_offset") {
                if (type == "immediate" && address < (1u << 24)) {
                    record.relative = address;
                    record.status = "success";
                } else {
                    record.status = "invalid_instruction";
                    record.detail = "invalid member displacement";
                }
            } else if (kind == "relative_to_offset") {
                const auto base_name = entry.at("base").get<std::string>();
                const auto base = db.offsets.find(qualified(module, base_name));
                if (type == "immediate" && base != db.offsets.end() && base->second.status == "success" &&
                    base->second.kind == "signature_address" && address < image->second.pe.image_size() &&
                    base->second.relative < image->second.pe.image_size() - address) {
                    record.relative = base->second.relative + address;
                    record.status = "success";
                } else {
                    record.status = "invalid_instruction";
                    record.detail = "base offset unavailable or derived target outside module";
                }
            } else if (in_module(image->second, address)) {
                record.relative = address - image->second.loaded.base;
                record.status = "success";
            } else {
                record.status = "invalid_module";
                record.detail = "resolved target outside source module";
            }
            db.offsets.emplace(key, std::move(record));
        } catch (const std::exception &e) {
            db.issues.push_back({"ERROR", "signature config", e.what()});
        }
    }
    return output;
}

void collect_interfaces(const ModuleImages &images, const MemoryReader &mem, DumpDatabase &db) {
    for (const auto &[module_name, image] : images) {
        const auto export_it = std::find_if(image.pe.exports().begin(), image.pe.exports().end(),
                                            [](const auto &e) { return e.name == "CreateInterface" && !e.forwarded; });
        if (export_it == image.pe.exports().end() || !image.loaded.base)
            continue;
        std::uint64_t function = image.loaded.base + export_it->rva;
        std::array<std::uint8_t, 32> code{};
        if (!mem.read(function, code))
            continue;
        if (code[0] == 0xE9) {
            const auto jump = resolve_relative_jump(function, code);
            if (!jump || !mem.read(*jump, code))
                continue;
            function = *jump;
        }
        std::optional<std::uint64_t> head;
        for (std::size_t i = 0; i + 7 <= code.size() && i < 12; ++i) {
            if ((code[i] == 0x48 || code[i] == 0x4C) && code[i + 1] == 0x8B && (code[i + 2] & 0xC7) == 0x05) {
                const auto slot = resolve_relative(function + i, std::span<const std::uint8_t>(code).subspan(i), 3, 7);
                if (slot) {
                    const auto candidate = mem.value<std::uint64_t>(*slot);
                    if (candidate) {
                        head = *candidate;
                        break;
                    }
                }
            }
        }
        if (!head) {
            db.issues.push_back({"WARN", module_name, "CreateInterface registry head not resolved"});
            continue;
        }
        if (!*head)
            continue;
        std::set<std::uint64_t> seen;
        std::size_t count{};
        while (*head && count < 1024 && seen.insert(*head).second) {
            const auto factory = mem.value<std::uint64_t>(*head);
            const auto name_ptr = mem.value<std::uint64_t>(*head + 8);
            const auto next = mem.value<std::uint64_t>(*head + 16);
            if (!factory || !name_ptr || !next || !in_module(image, *factory))
                break;
            const auto name = mem.string(*name_ptr, 96);
            if (!name || name->size() < 4 || name->size() > 80 ||
                !std::all_of(name->begin(), name->end(), [](unsigned char c) { return std::isalnum(c) || c == '_'; }))
                break;
            std::size_t digit = name->size();
            while (digit && std::isdigit(static_cast<unsigned char>((*name)[digit - 1])))
                --digit;
            Interface item{module_name,         *name,
                           name->substr(digit), static_cast<std::uint32_t>(*factory - image.loaded.base),
                           std::nullopt,        std::nullopt};
            if (const auto instance = factory_instance(mem, *factory); instance && in_module(image, *instance)) {
                item.instance_rva = static_cast<std::uint32_t>(*instance - image.loaded.base);
                if (const auto vtable = mem.value<std::uint64_t>(*instance); vtable && in_module(image, *vtable)) {
                    if (const auto data = image.pe.section(".rdata");
                        data && *vtable - image.loaded.base >= data->rva &&
                        *vtable - image.loaded.base < static_cast<std::uint64_t>(data->rva) + data->virtual_size)
                        item.vtable_rva = static_cast<std::uint32_t>(*vtable - image.loaded.base);
                }
            }
            const auto key = qualified(module_name, *name);
            if (!db.interfaces.emplace(key, std::move(item)).second)
                db.issues.push_back({"WARN", key, "duplicate interface registry name"});
            ++count;
            head = *next;
        }
        if (*head)
            db.issues.push_back({"WARN", module_name, "interface registry traversal stopped before list end"});
        if (!count)
            db.issues.push_back(
                {"WARN", module_name, "CreateInterface exported, but no validated registry entries found"});
    }
}

void collect_schema(const MemoryReader &mem, std::uint64_t address, const nlohmann::json &layout, DumpDatabase &db) {
    try {
        const auto registration = at<std::int32_t>(mem, address, offset(layout, "schema_system", "registration_count"));
        const auto vector = address + offset(layout, "schema_system", "scope_vector");
        const auto scope_count = mem.value<std::int32_t>(vector);
        const auto scope_array = at<std::uint64_t>(mem, vector, 8);
        if (!registration || !scope_count || !scope_array || *registration <= 0 || *registration > 1000000 ||
            *scope_count <= 0 || *scope_count > 512 || !*scope_array) {
            db.issues.push_back({"ERROR", "SchemaSystem",
                                 "profile validation failed: registration count or type-scope vector invalid"});
            return;
        }
        std::size_t valid_scopes{};
        for (std::int32_t i = 0; i < *scope_count; ++i) {
            const auto scope = mem.value<std::uint64_t>(*scope_array + static_cast<std::uint64_t>(i) * 8);
            if (!scope || !*scope)
                continue;
            const auto scope_name = mem.string(*scope + offset(layout, "type_scope", "name"), 256);
            if (!scope_name || scope_name->empty() || scope_name->size() > 200)
                continue;
            ++valid_scopes;
            const auto class_hash = *scope + offset(layout, "type_scope", "class_hash");
            for (const auto binding : hash_bindings(mem, class_hash, layout, db, *scope_name)) {
                auto name = ptr_string(mem, binding, offset(layout, "class", "name"));
                const auto size = at<std::int32_t>(mem, binding, offset(layout, "class", "size"));
                const auto field_count = at<std::int16_t>(mem, binding, offset(layout, "class", "field_count"));
                const auto metadata_count = at<std::int16_t>(mem, binding, offset(layout, "class", "metadata_count"));
                if (!name || name->empty() || !size || *size <= 0 || *size > (1 << 24) || !field_count ||
                    *field_count < 0 || *field_count > 8192 || !metadata_count || *metadata_count < 0 ||
                    *metadata_count > 128)
                    continue;
                const std::string &module_name = *scope_name;
                Class klass{*name,
                            module_name,
                            static_cast<std::uint32_t>(*size),
                            at<std::uint8_t>(mem, binding, offset(layout, "class", "alignment")).value_or(0),
                            {},
                            {},
                            {},
                            *scope_name};
                const auto metadata_ptr =
                    at<std::uint64_t>(mem, binding, offset(layout, "class", "metadata")).value_or(0);
                klass.metadata = read_metadata(mem, metadata_ptr, *metadata_count, layout);
                const auto base_ptr = at<std::uint64_t>(mem, binding, offset(layout, "class", "bases")).value_or(0);
                if (base_ptr) {
                    const auto base_class = at<std::uint64_t>(mem, base_ptr, offset(layout, "base", "class_ptr"));
                    if (base_class && *base_class) {
                        const auto base_name = ptr_string(mem, *base_class, offset(layout, "base", "name"));
                        if (base_name && !base_name->empty())
                            klass.bases.push_back({*base_name, module_name, std::nullopt});
                    }
                }
                const auto fields = at<std::uint64_t>(mem, binding, offset(layout, "class", "fields")).value_or(0);
                if (fields && *field_count)
                    for (std::int32_t j = 0; j < *field_count; ++j) {
                        const auto f = fields + static_cast<std::uint64_t>(j) * offset(layout, "field", "stride");
                        const auto fname = ptr_string(mem, f, offset(layout, "field", "name"));
                        const auto type_ptr = at<std::uint64_t>(mem, f, offset(layout, "field", "type"));
                        const auto foffset = at<std::int32_t>(mem, f, offset(layout, "field", "offset"));
                        if (!fname || fname->empty() || !type_ptr || !*type_ptr || !foffset || *foffset < 0 ||
                            *foffset >= *size)
                            continue;
                        const auto type_name = ptr_string(mem, *type_ptr, offset(layout, "type", "name"));
                        if (!type_name || type_name->empty())
                            continue;
                        Field field{*fname, *type_name, static_cast<std::uint32_t>(*foffset), 0, 0, false, false, {}};
                        const auto category =
                            at<std::uint8_t>(mem, *type_ptr, offset(layout, "type", "category")).value_or(255);
                        field.pointer = category == 1 || type_name->find('*') != std::string::npos;
                        if (category == 3)
                            field.array_count =
                                at<std::uint32_t>(mem, *type_ptr, offset(layout, "type", "array_size")).value_or(0);
                        if (field.pointer)
                            field.size = 8;
                        else {
                            const auto bracket = type_name->find('[');
                            const auto element_size = built_in_size(std::string_view(*type_name).substr(0, bracket));
                            if (element_size && field.array_count && field.array_count <= UINT32_MAX / element_size)
                                field.size = element_size * field.array_count;
                            else if (element_size && !field.array_count)
                                field.size = element_size;
                        }
                        const auto fmeta_count =
                            at<std::int32_t>(mem, f, offset(layout, "field", "metadata_count")).value_or(0);
                        const auto fmeta_ptr =
                            at<std::uint64_t>(mem, f, offset(layout, "field", "metadata")).value_or(0);
                        if (fmeta_count > 0 && fmeta_count <= 128)
                            field.metadata =
                                read_metadata(mem, fmeta_ptr, static_cast<std::uint32_t>(fmeta_count), layout);
                        for (const auto &metadata : field.metadata)
                            if (metadata.name.rfind("MNetwork", 0) == 0)
                                field.networked = true;
                        for (const auto &metadata : klass.metadata)
                            if (metadata.name == "MNetworkVarNames" &&
                                metadata.value.substr(0, metadata.value.find(':')) == field.name)
                                field.networked = true;
                        if (!klass.fields.emplace(field.name, std::move(field)).second)
                            db.issues.push_back(
                                {"WARN", qualified(module_name, *name), "duplicate field name: " + *fname});
                    }
                db.insert_class(std::move(klass));
            }
            const auto enum_hash = *scope + offset(layout, "type_scope", "enum_hash");
            for (const auto binding : hash_bindings(mem, enum_hash, layout, db, *scope_name)) {
                const auto name = ptr_string(mem, binding, offset(layout, "enum", "name"));
                const auto count = at<std::uint16_t>(mem, binding, offset(layout, "enum", "count"));
                if (!name || name->empty() || !count || *count > 8192)
                    continue;
                const std::string &enum_module = *scope_name;
                Enum value{*name,
                           enum_module,
                           at<std::uint8_t>(mem, binding, offset(layout, "enum", "size")).value_or(0),
                           at<std::uint8_t>(mem, binding, offset(layout, "enum", "alignment")).value_or(0),
                           {},
                           *scope_name};
                const auto data = at<std::uint64_t>(mem, binding, offset(layout, "enum", "values")).value_or(0);
                if (data)
                    for (std::uint32_t j = 0; j < *count; ++j) {
                        const auto e = data + static_cast<std::uint64_t>(j) * offset(layout, "enum_value", "stride");
                        const auto ename = ptr_string(mem, e, offset(layout, "enum_value", "name"));
                        const auto number = at<std::int64_t>(mem, e, offset(layout, "enum_value", "value"));
                        if (ename && number)
                            value.values.push_back({*ename, *number});
                    }
                std::sort(value.values.begin(), value.values.end(),
                          [](const auto &a, const auto &b) { return a.name < b.name; });
                db.insert_enum(std::move(value));
            }
        }
        for (auto &[key, klass] : db.classes) {
            (void)key;
            for (auto &base : klass.bases) {
                if (std::any_of(db.classes.begin(), db.classes.end(), [&](const auto &candidate) {
                        return candidate.second.scope == base.scope && candidate.second.name == base.name;
                    }))
                    continue;
                std::set<std::string> owners;
                for (const auto &[other_key, other] : db.classes) {
                    (void)other_key;
                    if (other.name == base.name)
                        owners.insert(other.scope);
                }
                if (owners.size() == 1)
                    base.scope = *owners.begin();
            }
        }
        if (!valid_scopes || db.classes.empty())
            db.issues.push_back(
                {"ERROR", "SchemaSystem", "no validated schema scopes/classes; layout may be outdated"});
    } catch (const std::exception &e) {
        db.issues.push_back({"ERROR", "SchemaSystem", e.what()});
    }
}

void collect_buttons(const MemoryReader &mem, std::uint64_t address, const nlohmann::json &layout, DumpDatabase &db) {
    try {
        auto current = address;
        std::set<std::uint64_t> seen;
        for (std::size_t i = 0; current && i < 512 && seen.insert(current).second; ++i) {
            const auto name = ptr_string(mem, current, offset(layout, "button", "name"), 64);
            if (!name || name->empty() || name->size() > 48)
                break;
            const auto module = db.modules.find("client.dll");
            const auto state = current + offset(layout, "button", "state");
            if (module != db.modules.end() && state >= module->second.base &&
                state - module->second.base < module->second.image_size) {
                db.buttons.emplace(*name,
                                   Button{*name, "client.dll", state - module->second.base, "KeyButton linked list"});
            }
            current = at<std::uint64_t>(mem, current, offset(layout, "button", "next")).value_or(0);
        }
        if (db.buttons.empty())
            db.issues.push_back({"WARN", "buttons", "no validated KeyButton entries found"});
    } catch (const std::exception &e) {
        db.issues.push_back({"ERROR", "buttons", e.what()});
    }
}
} // namespace cs2
