#include "fib_vector.h"

#include <catch2/catch.hpp>

TEST_CASE("Works when n == 0") {
    const auto expected = std::vector<int>{};
    auto nums = fibonacci(0);

    CHECK(nums == expected);
}

TEST_CASE("Works when n == 1") {
    auto nums = fibonacci(1);

    CHECK(!nums.empty());
    CHECK(nums.size() == 1);

    CHECK(nums[0] == 1);
    CHECK(nums.at(0) == 1);
}

TEST_CASE("Works when n == 2") {
    auto nums = fibonacci(2);

    CHECK(!nums.empty());
    CHECK(nums.size() == 2);

    CHECK(nums[0] == 1);
    CHECK(nums[1] == 1);
}

TEST_CASE("Works when n == 3") {
    auto nums = fibonacci(3);

    CHECK(!nums.empty());
    CHECK(nums.size() == 3);

    CHECK(nums[0] == 1);
    CHECK(nums[1] == 1);
    CHECK(nums[2] == 2);
}

TEST_CASE("Works when n == 12") {
    auto nums = fibonacci(12);

    CHECK(!nums.empty());
    CHECK(nums.size() == 12);

    CHECK(nums[0] == 1);
    CHECK(nums[1] == 1);
    CHECK(nums[2] == 2);
    CHECK(nums[3] == 3);
    CHECK(nums[4] == 5);
    CHECK(nums[5] == 8);
    CHECK(nums[6] == 13);
    CHECK(nums[7] == 21);
    CHECK(nums[8] == 34);
    CHECK(nums[9] == 55);
    CHECK(nums[10] == 89);
    CHECK(nums[11] == 144);
}