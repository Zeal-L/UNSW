#include "./vec3.h"

#include <catch2/catch.hpp>

TEST_CASE("tests SIZE") {
    REQUIRE(sizeof(vec3) == 3 * sizeof(double));
}

TEST_CASE("tests constructor") {
    vec3 v1;
    REQUIRE(v1.x == 0);
    REQUIRE(v1.y == 0);
    REQUIRE(v1.z == 0);
    vec3 v2{1};
    REQUIRE(v2.x == 1);
    REQUIRE(v2.y == 1);
    REQUIRE(v2.z == 1);
    vec3 v3{1, 2, 3};
    REQUIRE(v3.x == 1);
    REQUIRE(v3.y == 2);
    REQUIRE(v3.z == 3);
}

TEST_CASE("test other dimension") {
    vec3 v1{1, 2, 3};
    REQUIRE(v1.r == 1);
    REQUIRE(v1.g == 2);
    REQUIRE(v1.b == 3);
    REQUIRE(v1.s == 1);
    REQUIRE(v1.t == 2);
    REQUIRE(v1.p == 3);
}

TEST_CASE("tests copy constructor") {
    vec3 v1{1, 2, 3};
    vec3 v2 = v1;
    REQUIRE(v2.x == 1);
    REQUIRE(v2.y == 2);
    REQUIRE(v2.z == 3);
}

TEST_CASE("tests destructor") {
    vec3 *v1 = new vec3{1, 2, 3};
    delete v1;
}

// TEST_CASE("tests move constructor, should not compile") {
//     vec3 v1{1, 2, 3};
//     vec3 v2 = std::move(v1);
// }