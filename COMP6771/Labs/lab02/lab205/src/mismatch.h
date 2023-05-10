#ifndef COMP6771_MISMATCH_H
#define COMP6771_MISMATCH_H

#include <utility>
#include <vector>

// equivalent to: typedef typename std::vector<int>::iterator iter;
using iter = typename std::vector<int>::iterator;

/**
 * Finds the first mismatching pair of elements from v1 and v2.
 * Two elements are mismatched if they do not compare equal AND they have different indices.
 * v1.end() != v2.end() is always true i.e. the end iterators of two ranges never compare equal.
 * @param v1 One range of a vector of ints
 * @param v2 Another range of a vector of ints
 * @return A pair consisting of iterators into v1 and v2 respectively where the first mismatch is.
 *         Either element in the pair may be end() to signal that the end of that range was reached
 */
auto mismatch(std::vector<int> &v1, std::vector<int> &v2) -> std::pair<iter, iter>;

#endif // COMP6771_MISMATCH_H