#ifndef COMP6771_MICROBENCHMARK_H
#define COMP6771_MICROBENCHMARK_H

#include <deque>
#include <list>
#include <vector>

struct timings {
    double list_avg_time;
    double deque_avg_time;
    double vec_avg_time;
};

/**
 * In the benchmark, the following steps need to be performed in-order:
 * 1. A container (can be any sequential container) needs to be filled with n_elems random numbers.
 * 2. This container of numbers needs to be copied to a std::list, std::deque, and std::vector.
 * 3. A number, n, to find needs to be randomly generated.
 * 4. The time it takes each of the containers to lookup n with std::find() should be recorded and stored.
 * 4. Steps 1 - 4 should be repeated n_repetitions times.
 * 5. Return a `timings` struct, where each member is the sum of that container's timings / n_repetitions.
 * 
 * @param n_repetitions - the number of times the above procedure should be repeated.
 * @param n_elems - the number of elements to fill each container with
 */
auto microbenchmark_lookup(int n_repetitions, int n_elems) -> timings;

#endif // COMP6771_MICROBENCHMARK_H