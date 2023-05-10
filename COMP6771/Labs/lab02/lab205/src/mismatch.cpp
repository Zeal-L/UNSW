#include "mismatch.h"

auto mismatch(std::vector<int> &v1, std::vector<int> &v2) -> std::pair<iter, iter> {
    auto iter1 = v1.begin(), iter2 = v2.begin();
    while (iter1 != v1.end() && iter2 != v2.end()) {
        if (*iter1 != *iter2) {
            return {iter1, iter2};
        }
        ++iter1, ++iter2;
    }
    return {iter1, iter2};
}