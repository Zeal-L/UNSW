#include "./register.h"

#include <catch2/catch.hpp>

TEST_CASE("size2reg with sizes that fit in register", "[size2reg]") {
    CHECK(std::is_same_v<size2reg_t<1>, std::uint8_t>);
    CHECK(std::is_same_v<size2reg_t<2>, std::uint16_t>);
    CHECK(std::is_same_v<size2reg_t<3>, std::uint32_t>);
    CHECK(std::is_same_v<size2reg_t<4>, std::uint32_t>);
    CHECK(std::is_same_v<size2reg_t<5>, std::uint64_t>);
    CHECK(std::is_same_v<size2reg_t<6>, std::uint64_t>);
    CHECK(std::is_same_v<size2reg_t<7>, std::uint64_t>);
    CHECK(std::is_same_v<size2reg_t<8>, std::uint64_t>);

}

TEST_CASE("size2reg with sizes that do not fit in register", "[size2reg]") {
    CHECK(std::is_same_v<size2reg_t<9>, void>);
    CHECK(std::is_same_v<size2reg_t<10>, void>);
    CHECK(std::is_same_v<size2reg_t<11>, void>);
    CHECK(std::is_same_v<size2reg_t<12>, void>);
    CHECK(std::is_same_v<size2reg_t<13>, void>);
    CHECK(std::is_same_v<size2reg_t<14>, void>);
    CHECK(std::is_same_v<size2reg_t<15>, void>);
    CHECK(std::is_same_v<size2reg_t<16>, void>);
}

TEST_CASE("is_passable_in_register with fundamental types") {
    CHECK(is_passable_in_register_v<int>);
    CHECK(is_passable_in_register_v<long>);
    CHECK(is_passable_in_register_v<char>);
    CHECK(is_passable_in_register_v<double>);
    CHECK(is_passable_in_register_v<bool>);
    CHECK(is_passable_in_register_v<std::int16_t>);
    CHECK(is_passable_in_register_v<std::uint32_t>);
}

TEST_CASE("is_passable_in_register with trivial types") {
    CHECK(is_passable_in_register_v<int *>);
    CHECK(is_passable_in_register_v<char *>);
    CHECK(is_passable_in_register_v<std::nullptr_t *>);
    CHECK(is_passable_in_register_v<std::nullptr_t **>);
    CHECK(is_passable_in_register_v<std::nullptr_t ***>);
}