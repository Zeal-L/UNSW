#ifndef COMP6771_SETDIFF_H
#define COMP6771_SETDIFF_H

#include <vector>

/**
 * Removes all occurrences of each element in blacklist from vec_set
 * @param vec_set The vector set who will have its elements removed
 * @param blacklist The list of elements to remove
 */
auto set_difference(std::vector<char> &vec_set, const std::vector<char> &blacklist) -> void;

#endif // COMP6771_SETDIFF_H