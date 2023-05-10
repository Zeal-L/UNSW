#include "permutation.h"
#include <catch2/catch.hpp>

TEST_CASE("permutation simple") {
    SECTION("permutation simple 1") {
        std::string x = "abc";
        std::string y = "cba";
        REQUIRE(is_permutation(x, y));
    }
    SECTION("permutation simple 2") {
        std::string x = "abc";
        std::string y = "cb";
        REQUIRE_FALSE(is_permutation(x, y));
    }
}
TEST_CASE("permutation empty") {
    SECTION("permutation empty 1") {
        std::string x = "";
        std::string y = "";
        REQUIRE(is_permutation(x, y));
    }
    SECTION("permutation empty 2") {
        std::string x = "";
        std::string y = "abc";
        REQUIRE_FALSE(is_permutation(x, y));
    }
    SECTION("permutation empty 3") {
        std::string x = "abc";
        std::string y = "";
        REQUIRE_FALSE(is_permutation(x, y));
    }
}

TEST_CASE("permutation complex") {
    SECTION("permutation complex 1") {
        std::string x = "aaaaxx";
        std::string y = "axxaaa";
        REQUIRE(is_permutation(x, y));
    }
    SECTION("permutation complex 2") {
        std::string x = "aassssaaxx";
        std::string y = "axxssszaaa";
        REQUIRE_FALSE(is_permutation(x, y));
    }
}