#include "./sort_descending.h"
#include <catch2/catch.hpp>


TEST_CASE("reverse date set") {
    auto nums = std::vector<int>{1, 2, 3, 4, 5, 6, 7, 8};
    sort_descending(nums);
    CHECK(nums == std::vector<int>{8, 7, 6, 5, 4, 3, 2, 1});
}

TEST_CASE("in order date set") {
    auto nums = std::vector<int>{8, 7, 6, 5, 4, 3, 2, 1};
    sort_descending(nums);
    CHECK(nums == std::vector<int>{8, 7, 6, 5, 4, 3, 2, 1});
}

TEST_CASE("random date set") {
    auto nums = std::vector<int>{1, 3, 5, 7, 2, 4, 6, 8};
    sort_descending(nums);
    CHECK(nums == std::vector<int>{8, 7, 6, 5, 4, 3, 2, 1});
}