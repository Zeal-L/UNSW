#include "mismatch.h"
#include <catch2/catch.hpp>
#include <iostream>


TEST_CASE("Left range is empty") {
    auto v1 = std::vector<int>{};
    auto v2 = std::vector<int>{1, 2, 3};

    // this is called a structured binding. Available from C++17
    // See: https://en.cppreference.com/w/cpp/language/structured_binding
    const auto &[iter1, iter2] = mismatch(v1, v2);

    CHECK(iter1 == v1.end());
    REQUIRE(iter2 != v2.end());
    REQUIRE(*iter2 == 1);
}

TEST_CASE("Right range is empty") {
    auto v1 = std::vector<int>{1, 2, 3};
    auto v2 = std::vector<int>{};

    const auto &[iter1, iter2] = mismatch(v1, v2);

    REQUIRE(iter1 != v1.end());
    CHECK(iter2 == v2.end());
    REQUIRE(*iter1 == 1);
}

TEST_CASE("Both range is empty") {
    auto v1 = std::vector<int>{};
    auto v2 = std::vector<int>{};

    const auto &[iter1, iter2] = mismatch(v1, v2);

    CHECK(iter1 == v1.end());
    CHECK(iter2 == v2.end());
}

TEST_CASE("mismatch simple") {
    SECTION("mismatch all matching") {
        auto v1 = std::vector<int>{1, 2, 3};
        auto v2 = std::vector<int>{1, 2, 3};

        const auto &[iter1, iter2] = mismatch(v1, v2);

        CHECK(iter1 == v1.end());
        CHECK(iter2 == v2.end());
        CHECK(v1.end() != v2.end());
    }
    SECTION("mismatch no matching") {
        auto v1 = std::vector<int>{1, 2, 3};
        auto v2 = std::vector<int>{4, 5, 6};

        const auto &[iter1, iter2] = mismatch(v1, v2);

        REQUIRE(iter1 != v1.end());
        REQUIRE(iter2 != v2.end());
        CHECK(*iter1 == 1);
        CHECK(*iter2 == 4);
    }
}

TEST_CASE("mismatch complex") {
    SECTION("mismatch at the beginning") {
        auto v1 = std::vector<int>{1, 2, 3};
        auto v2 = std::vector<int>{2, 2, 3};

        const auto &[iter1, iter2] = mismatch(v1, v2);

        REQUIRE(iter1 != v1.end());
        REQUIRE(iter2 != v2.end());
        CHECK(*iter1 == 1);
        CHECK(*iter2 == 2);
    }
    SECTION("mismatch at the end") {
        auto v1 = std::vector<int>{1, 2, 3};
        auto v2 = std::vector<int>{1, 2, 4};

        const auto &[iter1, iter2] = mismatch(v1, v2);
        CHECK(v1.end() != v2.end());
        CHECK(*iter1 == 3);
        CHECK(*iter2 == 4);
    }
    SECTION("mismatch in the middle") {
        auto v1 = std::vector<int>{1, 2, 3};
        auto v2 = std::vector<int>{1, 4, 3};

        const auto &[iter1, iter2] = mismatch(v1, v2);

        REQUIRE(iter1 != v1.end());
        REQUIRE(iter2 != v2.end());
        CHECK(*iter1 == 2);
        CHECK(*iter2 == 4);
    }
}

