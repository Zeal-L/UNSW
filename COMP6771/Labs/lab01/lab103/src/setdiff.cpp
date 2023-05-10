#include "setdiff.h"

#include <algorithm>
#include <vector>

auto set_difference(std::vector<char> &vec_set, const std::vector<char> &blacklist) -> void {
    if (vec_set.empty() || blacklist.empty()) return;
    auto it = std::find(vec_set.begin(), vec_set.end(), blacklist[0]);
    if (it != vec_set.end()) {
        vec_set.erase(it);
        set_difference(vec_set, std::vector<char>(blacklist.begin(), blacklist.end()));
    } else {
        set_difference(vec_set, std::vector<char>(blacklist.begin() + 1, blacklist.end()));
    }
}
