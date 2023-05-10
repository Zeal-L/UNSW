#include "invert.h"

auto invert(const std::map<std::string, int> &mp) -> std::map<int, std::string> {
    auto result = std::map<int, std::string>{};

    for (auto const& [key, value] : mp) {
        if (result.find(value) != result.end()) {
            if (key.size() > result[value].size()) {
                result[value] = key;
            }
        } else {
            result[value] = key;
        }
    }

    return result;
}