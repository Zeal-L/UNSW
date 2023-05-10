#include "stats.h"

#include <catch2/catch.hpp>

TEST_CASE("Check read_marks reads from file") {
    auto const marks = read_marks("./marks.txt");
    CHECK(marks.size() == 14);
    CHECK(marks[0] == 2);
    CHECK(marks[1] == 14);
    CHECK(marks[2] == 90);
}

TEST_CASE("calculate_stats get correct stats from marks") {
    auto const marks = read_marks("./marks.txt");
    auto const stats = calculate_stats(marks);
    CHECK(stats.avg == 50);
    CHECK(stats.median == 56);
    CHECK(stats.highest == 100);
    CHECK(stats.lowest == 2);
}