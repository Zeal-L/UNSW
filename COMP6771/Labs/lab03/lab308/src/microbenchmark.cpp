#include "microbenchmark.h"

#include <random>
#include <chrono>
#include <vector>
#include <list>
#include <deque>
#include <algorithm>

constexpr auto LOWER_BOUND = 0;
constexpr auto UPPER_BOUND = 500'000; // C++11 onwards allows ' as a number separator

// A useful function to generate random numbers in a mathematically sound way
auto rand() -> int {
    static auto rd = std::random_device{};   // Will be used to obtain a seed for the random number engine
    static auto gen = std::mt19937(rd());      // Standard mersenne_twister_engine seeded with rd()
    static auto distrib = std::uniform_int_distribution<>(LOWER_BOUND, UPPER_BOUND);

    return distrib(gen);
}

auto microbenchmark_lookup(int n_repetitions, int n_elems) -> timings {
    timings t = {0, 0, 0};
    auto temp = std::vector<int>(static_cast<std::vector<int>::size_type>(n_elems));
    std::generate(temp.begin(), temp.end(), rand);

    for (int i = 0; i < n_repetitions; ++i) {
        auto rand_num = rand() % n_elems;

        auto vec = std::vector<int>(temp);
        auto start = std::chrono::high_resolution_clock::now();
        std::find(vec.begin(), vec.end(), rand_num);
        auto end = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::nanoseconds>(end - start);
        t.vec_avg_time = t.vec_avg_time + static_cast<double>(duration.count());


        auto list = std::list<int>(temp.begin(), temp.end());
        start = std::chrono::high_resolution_clock::now();
        std::find(list.begin(), list.end(), rand_num);
        end = std::chrono::high_resolution_clock::now();
        duration = std::chrono::duration_cast<std::chrono::nanoseconds>(end - start);
        t.list_avg_time = t.list_avg_time + static_cast<double>(duration.count());

        auto deque = std::deque<int>(temp.begin(), temp.end());
        start = std::chrono::high_resolution_clock::now();
        std::find(deque.begin(), deque.end(), rand_num);
        end = std::chrono::high_resolution_clock::now();
        duration = std::chrono::duration_cast<std::chrono::nanoseconds>(end - start);
        t.deque_avg_time = t.deque_avg_time + static_cast<double>(duration.count());
    }

    t.vec_avg_time = t.vec_avg_time / n_repetitions;
    t.list_avg_time = t.list_avg_time / n_repetitions;
    t.deque_avg_time = t.deque_avg_time / n_repetitions;

    return t;
}
