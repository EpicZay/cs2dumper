#pragma once
#include "database/database.hpp"
#include <filesystem>
#include <set>
#include <string>
#include <string_view>

namespace cs2 {
std::string identifier(std::string_view source, std::string_view language);
std::string hex(std::uint64_t value);
bool generate(const DumpDatabase &db, const std::filesystem::path &directory, const std::set<std::string> &formats,
              std::string &error);
} // namespace cs2
