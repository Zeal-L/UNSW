#include "mixer.h"

#include <catch2/catch.hpp>


TEST_CASE("wacky_colour legal combinations") {
    SECTION("red + green = yellow") {
        REQUIRE(wacky_colour(paint::RED, paint::GREEN) == paint::YELLOW);
    }
    SECTION("red + blue = magenta") {
        REQUIRE(wacky_colour(paint::RED, paint::BLUE) == paint::MAGENTA);
    }
    SECTION("green + blue = cyan") {
        REQUIRE(wacky_colour(paint::GREEN, paint::BLUE) == paint::CYAN);
    }
    SECTION("yellow + magenta = brown") {
        REQUIRE(wacky_colour(paint::YELLOW, paint::MAGENTA) == paint::BROWN);
    }
    SECTION("yellow + cyan = brown") {
        REQUIRE(wacky_colour(paint::YELLOW, paint::CYAN) == paint::BROWN);
    }
    SECTION("cyan + magenta = brown") {
        REQUIRE(wacky_colour(paint::CYAN, paint::MAGENTA) == paint::BROWN);
    }
    SECTION("brown + brown = brown") {
        REQUIRE(wacky_colour(paint::BROWN, paint::BROWN) == paint::BROWN);
    }
}

TEST_CASE("wacky_colour ilegal combinations") {
    SECTION("green + red = no colour") {
        REQUIRE(wacky_colour(paint::GREEN, paint::RED) == std::nullopt);
    }
    SECTION("blue + red = no colour") {
        REQUIRE(wacky_colour(paint::BLUE, paint::RED) == std::nullopt);
    }
    SECTION("blue + green = no colour") {
        REQUIRE(wacky_colour(paint::BLUE, paint::GREEN) == std::nullopt);
    }
    SECTION("magenta + yellow = no colour") {
        REQUIRE(wacky_colour(paint::MAGENTA, paint::YELLOW) == std::nullopt);
    }
    SECTION("cyan + yellow = no colour") {
        REQUIRE(wacky_colour(paint::CYAN, paint::YELLOW) == std::nullopt);
    }
    SECTION("magenta + cyan = no colour") {
        REQUIRE(wacky_colour(paint::MAGENTA, paint::CYAN) == std::nullopt);
    }
}

TEST_CASE("mix legal combinations") {
    SECTION("red + green + magenta = brown") {
        std::vector<paint> paints = {paint::RED, paint::GREEN, paint::MAGENTA};
        REQUIRE(mix(paints, wacky_colour) == paint::BROWN);
    }
    SECTION("red + green + cyan = brown") {
        std::vector<paint> paints = {paint::RED, paint::GREEN, paint::CYAN};
        REQUIRE(mix(paints, wacky_colour) == paint::BROWN);
    }
}

TEST_CASE("mix ilegal combinations") {
    SECTION("red + green + blue = no colour") {
        std::vector<paint> paints = {paint::RED, paint::GREEN, paint::BLUE};
        REQUIRE(mix(paints, wacky_colour) == std::nullopt);
    }
    SECTION("red + green + blue + magenta = no colour") {
        std::vector<paint> paints = {paint::RED, paint::GREEN, paint::BLUE, paint::MAGENTA};
        REQUIRE(mix(paints, wacky_colour) == std::nullopt);
    }
}

TEST_CASE("mix empty vector") {
    std::vector<paint> paints = {};
    REQUIRE(mix(paints, wacky_colour) == std::nullopt);
}

TEST_CASE("mix vector with one element") {
    std::vector<paint> paints = {paint::RED};
    REQUIRE(mix(paints, wacky_colour) == std::nullopt);
}