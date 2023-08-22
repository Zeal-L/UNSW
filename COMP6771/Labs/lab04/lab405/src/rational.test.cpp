#include "rational.h"

#include <catch2/catch.hpp>

TEST_CASE("test make_rational") {
    rational_number r = rational_number::make_rational(1, 2).value();
    REQUIRE(r.value() == 0.5);
}

TEST_CASE("test invalid make_rational") {
    auto r = rational_number::make_rational(1, 0);
    REQUIRE(r.has_value() == false);
}

TEST_CASE("test add") {
    rational_number r1 = rational_number::make_rational(1, 2).value();
    rational_number r2 = rational_number::make_rational(1, 3).value();
    rational_number r3 = add(r1, r2);
    REQUIRE(r3.value() == 5.0 / 6.0);
}

TEST_CASE("test sub") {
    rational_number r1 = rational_number::make_rational(1, 2).value();
    rational_number r2 = rational_number::make_rational(1, 3).value();
    rational_number r3 = sub(r1, r2);
    REQUIRE(r3.value() == 1.0 / 6.0);
}

TEST_CASE("test mul") {
    rational_number r1 = rational_number::make_rational(1, 2).value();
    rational_number r2 = rational_number::make_rational(1, 3).value();
    rational_number r3 = mul(r1, r2);
    REQUIRE(r3.value() == 1.0 / 6.0);
}

TEST_CASE("test div") {
    rational_number r1 = rational_number::make_rational(1, 2).value();
    rational_number r2 = rational_number::make_rational(1, 3).value();
    rational_number r3 = div(r1, r2).value();
    REQUIRE(r3.value() == 3.0 / 2.0);
}

TEST_CASE("test eq") {
    rational_number r1 = rational_number::make_rational(1, 2).value();
    rational_number r2 = rational_number::make_rational(1, 3).value();
    REQUIRE(eq(r1, r2) == false);
}

TEST_CASE("test ne") {
    rational_number r1 = rational_number::make_rational(1, 2).value();
    rational_number r2 = rational_number::make_rational(1, 3).value();
    REQUIRE(ne(r1, r2) == true);
}

TEST_CASE("Instance size") {
    rational_number r = rational_number::make_rational(1, 2).value();
    REQUIRE(sizeof(r) <= 16);
}