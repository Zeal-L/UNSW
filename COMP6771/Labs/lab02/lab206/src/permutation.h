#ifndef COMP6771_PERMUTATION_H
#define COMP6771_PERMUTATION_H

#include <string>

/**
 * Determines if the string _x_ is a permutation of the string _y_.
 * It is possible for one or either of these strings to be the empty string.
 */
auto is_permutation(const std::string &x, const std::string &y) -> bool;

#endif // COMP6771_PERMUTATION_H