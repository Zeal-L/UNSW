#include "microbenchmark.h"

#include <catch2/catch.hpp>
#include <iostream>

TEST_CASE("mark my bench") {
    auto const t = microbenchmark_lookup(1000, 1000);
    CHECK(t.vec_avg_time > 0);
    CHECK(t.list_avg_time > 0);
    CHECK(t.deque_avg_time > 0);
    std::cout << "vec_avg_time: " << t.vec_avg_time << std::endl;
    std::cout << "list_avg_time: " << t.list_avg_time << std::endl;
    std::cout << "deque_avg_time: " << t.deque_avg_time << std::endl;
}