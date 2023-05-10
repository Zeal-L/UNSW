#ifndef COMP6771_FIB_VECTOR_H
#define COMP6771_FIB_VECTOR_H

#include <vector>

/**
 * @brief Calculates upto and including the n'th fibonacci number.
 * 
 * For example, fibonacci(5) returns {1, 2, 3, 5, 8}.
 * 
 * @param n If n < 1, return an empty vector.
 */
auto fibonacci(int n) -> std::vector<int>;

#endif // COMP6771_FIB_VECTOR_H