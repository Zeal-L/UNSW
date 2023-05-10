#include "./ferrari.h"

#include <catch2/catch.hpp>

TEST_CASE("default constructor") {
    ferrari f = ferrari();
    REQUIRE(f.get_details().first == "unknown");
    REQUIRE(f.get_details().second == 6771);
    REQUIRE(f.vroom() == "");
}

TEST_CASE("regular constructor") {
    ferrari f = ferrari("John", 1234);
    REQUIRE(f.get_details().first == "John");
    REQUIRE(f.get_details().second == 1234);
    REQUIRE(f.vroom() == "");
}

TEST_CASE("drive -- less than 20") {
    ferrari f = ferrari("John", 1234);
    f.drive(10);
    REQUIRE(f.vroom() == "");
}

TEST_CASE("drive -- less than 80") {
    ferrari f = ferrari("John", 1234);
    f.drive(50);
    REQUIRE(f.vroom() == "vroom!!");
}

TEST_CASE("drive -- more than 80") {
    ferrari f = ferrari("John", 1234);
    f.drive(200);
    REQUIRE(f.vroom() == "VROOOOOOOOM!!!");
}

TEST_CASE("default speed") {
    ferrari f = ferrari("John", 1234);
    REQUIRE(f.vroom() == "");
    f.drive();
    REQUIRE(f.vroom() == "VROOOOOOOOM!!!");
}