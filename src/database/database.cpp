#include "database/database.hpp"
#include <algorithm>

namespace cs2 {
std::string qualified(std::string_view scope, std::string_view name) {
    return std::string(scope) + "::" + std::string(name);
}
bool DumpDatabase::insert_class(Class value) {
    const auto key =
        qualified(value.scope, value.type_scope.empty() ? value.name : qualified(value.type_scope, value.name));
    if (value.name.empty() || value.scope.empty() || classes.contains(key)) {
        issues.push_back({"WARN", key, "invalid or duplicate class"});
        return false;
    }
    classes.emplace(key, std::move(value));
    return true;
}
bool DumpDatabase::insert_enum(Enum value) {
    const auto key =
        qualified(value.scope, value.type_scope.empty() ? value.name : qualified(value.type_scope, value.name));
    if (value.name.empty() || value.scope.empty() || enums.contains(key)) {
        issues.push_back({"WARN", key, "invalid or duplicate enum"});
        return false;
    }
    enums.emplace(key, std::move(value));
    return true;
}
std::optional<Field> DumpDatabase::inherited_field(const std::string &scope, const std::string &class_name,
                                                   const std::string &field_name) const {
    std::set<std::string> visited;
    const auto search = [&](const auto &self, const std::string &s, const std::string &name,
                            std::uint64_t added) -> std::optional<Field> {
        const auto key = qualified(s, name);
        if (!visited.insert(key).second)
            return std::nullopt;
        const Class *found = nullptr;
        const Class *preferred = nullptr;
        std::size_t candidates{}, preferred_count{};
        for (const auto &[candidate_key, candidate] : classes) {
            (void)candidate_key;
            if (candidate.scope != s || candidate.name != name)
                continue;
            found = &candidate;
            ++candidates;
            if (candidate.type_scope == s) {
                preferred = &candidate;
                ++preferred_count;
            }
        }
        if (preferred_count == 1)
            found = preferred;
        else if (candidates != 1)
            return std::nullopt;
        if (!found)
            return std::nullopt;
        if (const auto it = found->fields.find(field_name); it != found->fields.end()) {
            auto result = it->second;
            if (added + result.offset > UINT32_MAX)
                return std::nullopt;
            result.offset += static_cast<std::uint32_t>(added);
            return result;
        }
        for (const auto &base : found->bases)
            if (base.offset)
                if (auto field = self(self, base.scope.empty() ? s : base.scope, base.name, added + *base.offset))
                    return field;
        return std::nullopt;
    };
    return search(search, scope, class_name, 0);
}
std::size_t DumpDatabase::field_count() const {
    std::size_t total{};
    for (const auto &[key, c] : classes) {
        (void)key;
        total += c.fields.size();
    }
    return total;
}
void DumpDatabase::validate() {
    for (const auto &[key, c] : classes) {
        if (!c.size || c.size > (1u << 24))
            issues.push_back({"WARN", key, "class size outside expected range"});
        for (const auto &[name, f] : c.fields) {
            if (name.empty() || f.type.empty())
                issues.push_back({"WARN", key, "field name or type is empty"});
            if (c.size && f.offset >= c.size)
                issues.push_back({"WARN", key + "::" + name, "field offset exceeds class size"});
        }
        for (const auto &base : c.bases) {
            const auto owner = base.scope.empty() ? c.scope : base.scope;
            const auto base_key = qualified(owner, base.name);
            if (owner == c.scope && base.name == c.name)
                issues.push_back({"WARN", key, "self inheritance"});
            if (std::none_of(classes.begin(), classes.end(), [&](const auto &other) {
                    return other.second.scope == owner && other.second.name == base.name;
                }))
                issues.push_back({"WARN", key, "base class unavailable: " + base_key});
        }
    }
}
} // namespace cs2
