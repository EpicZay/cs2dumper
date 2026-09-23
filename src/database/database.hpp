#pragma once
#include <cstdint>
#include <map>
#include <optional>
#include <set>
#include <string>
#include <vector>

namespace cs2 {
struct Issue {
    std::string level, context, message;
};
struct ModuleRecord {
    std::string name, path, status;
    std::uint64_t base{};
    std::uint32_t image_size{}, timestamp{};
    std::map<std::string, std::uint32_t> exports;
};
struct Metadata {
    std::string name, value;
};
struct Field {
    std::string name, type;
    std::uint32_t offset{}, size{}, array_count{};
    bool pointer{}, networked{};
    std::vector<Metadata> metadata;
};
struct BaseClass {
    std::string name, scope;
    std::optional<std::uint32_t> offset;
};
struct Class {
    std::string name, scope;
    std::uint32_t size{}, alignment{};
    std::vector<BaseClass> bases;
    std::map<std::string, Field> fields;
    std::vector<Metadata> metadata;
    std::string type_scope;
};
struct EnumValue {
    std::string name;
    std::int64_t value{};
};
struct Enum {
    std::string name, scope;
    std::uint32_t size{}, alignment{};
    std::vector<EnumValue> values;
    std::string type_scope;
};
struct Interface {
    std::string module, name, version;
    std::uint32_t factory_rva{};
    std::optional<std::uint32_t> instance_rva, vtable_rva;
};
struct Offset {
    std::string name, module, method, signature, status, kind;
    std::uint64_t relative{};
    std::string detail;
};
struct Button {
    std::string name, module;
    std::uint64_t relative{};
    std::string method;
};
struct DumpDatabase {
    std::map<std::string, ModuleRecord> modules;
    std::map<std::string, Class> classes;
    std::map<std::string, Enum> enums;
    std::map<std::string, Interface> interfaces;
    std::map<std::string, Offset> offsets;
    std::map<std::string, Button> buttons;
    std::vector<Issue> issues;
    std::string steam_build_id;
    std::optional<std::uint32_t> game_build;
    bool insert_class(Class value);
    bool insert_enum(Enum value);
    std::optional<Field> inherited_field(const std::string &scope, const std::string &class_name,
                                         const std::string &field_name) const;
    void validate();
    std::size_t field_count() const;
};
std::string qualified(std::string_view scope, std::string_view name);
} // namespace cs2
