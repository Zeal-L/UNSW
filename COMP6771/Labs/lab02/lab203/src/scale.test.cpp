#include "scale.h"
#include <catch2/catch.hpp>

TEST_CASE("scales normal") {
    SECTION("scales by 0") {
        std::vector<int> ivec{1, 2, 3, 4, 5};
        std::vector<double> dvec{0.0, 0.0, 0.0, 0.0, 0.0};
        REQUIRE(scale(ivec, 0) == dvec);
    }
    SECTION("scales by 0.5 default") {
        std::vector<int> ivec{1, 2, 3, 4, 5};
        std::vector<double> dvec{0.5, 1.0, 1.5, 2.0, 2.5};
        REQUIRE(scale(ivec) == dvec);
    }
    SECTION("scales by 1") {
        std::vector<int> ivec{1, 2, 3, 4, 5};
        std::vector<double> dvec{1.0, 2.0, 3.0, 4.0, 5.0};
        REQUIRE(scale(ivec, 1) == dvec);
    }
    SECTION("scales by 2") {
        std::vector<int> ivec{1, 2, 3, 4, 5};
        std::vector<double> dvec{2.0, 4.0, 6.0, 8.0, 10.0};
        REQUIRE(scale(ivec, 2) == dvec);
    }

}