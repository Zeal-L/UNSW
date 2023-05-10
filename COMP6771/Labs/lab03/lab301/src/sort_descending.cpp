#include "sort_descending.h"
#include <algorithm>

auto sort_descending(std::vector<int>& numbers) -> void {
    std::sort(numbers.begin(), numbers.end(), std::greater<int>());
}
