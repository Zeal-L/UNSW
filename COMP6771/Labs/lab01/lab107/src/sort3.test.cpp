#include "sort3.h"
#include <catch2/catch.hpp>

TEST_CASE("sort3_int") {
    SECTION("already sorted") {
        int a = 1;
        int b = 2;
        int c = 3;
        sort3(a, b, c);
        REQUIRE(a == 1);
        REQUIRE(b == 2);
        REQUIRE(c == 3);
    }
    SECTION("reverse sorted") {
        int a = 3;
        int b = 2;
        int c = 1;
        sort3(a, b, c);
        REQUIRE(a == 1);
        REQUIRE(b == 2);
        REQUIRE(c == 3);
    }
    SECTION("middle") {
        int a = 1;
        int b = 3;
        int c = 2;
        sort3(a, b, c);
        REQUIRE(a == 1);
        REQUIRE(b == 2);
        REQUIRE(c == 3);
    }
}

TEST_CASE("sort3_string") {
    SECTION("already sorted") {
        std::string a = "a";
        std::string b = "b";
        std::string c = "c";
        sort3(a, b, c);
        REQUIRE(a == "a");
        REQUIRE(b == "b");
        REQUIRE(c == "c");
    }
    SECTION("reverse sorted") {
        std::string a = "c";
        std::string b = "b";
        std::string c = "a";
        sort3(a, b, c);
        REQUIRE(a == "a");
        REQUIRE(b == "b");
        REQUIRE(c == "c");
    }
    SECTION("middle") {
        std::string a = "a";
        std::string b = "c";
        std::string c = "b";
        sort3(a, b, c);
        REQUIRE(a == "a");
        REQUIRE(b == "b");
        REQUIRE(c == "c");
    }
}
