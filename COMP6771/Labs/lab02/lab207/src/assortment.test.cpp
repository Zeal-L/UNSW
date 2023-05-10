#include "assortment.h"

#include <catch2/catch.hpp>


TEST_CASE("Sorting vectors of ints") {
    auto ivec = std::vector<int>{6, 7, 7, 1};
    const auto expected = std::vector<int>{1, 6, 7, 7};

    sort(ivec);

    CHECK(ivec == expected);
}

TEST_CASE("Sorting arrays of ints") {
    auto iarr = std::array<int, 4>{6, 7, 7, 1};
    const auto expected = std::array<int, 4>{1, 6, 7, 7};

    sort(iarr);

    CHECK(iarr == expected);
}

TEST_CASE("Sorting doubly-linked lists of ints") {
    auto ilist = std::list<int>{6, 7, 7, 1};
    const auto expected = std::list<int>{1, 6, 7, 7};

    sort(ilist);

    CHECK(ilist == expected);
}