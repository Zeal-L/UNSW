#include "fib_vector.h"
#include <iostream>

auto fibonacci(int n) -> std::vector<int> {
    auto nums = std::vector<int>{};
    for (auto i = 0; i < n; i++) {
        if (i == 0 || i == 1) {
            nums.push_back(1);
        } else  {
            auto a = static_cast<std::vector<int>::size_type>(i - 1);
            auto b = static_cast<std::vector<int>::size_type>(i - 2);
            nums.push_back(nums[a] + nums[b]);
        }
    }
    return nums;
}

