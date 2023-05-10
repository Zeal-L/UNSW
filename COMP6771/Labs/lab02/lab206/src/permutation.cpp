#include "permutation.h"
#include <algorithm>

auto is_permutation(const std::string &x, const std::string &y) -> bool {
    if (x.empty() && y.empty()) {
        return true;
    }
    if (x.size() != y.size()) {
        return false;
    }

    std::string x_sorted = x;
    std::string y_sorted = y;
    std::sort(x_sorted.begin(), x_sorted.end());
    std::sort(y_sorted.begin(), y_sorted.end());

    return x_sorted == y_sorted;
}
