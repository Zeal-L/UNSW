#ifndef COMP6771_STATS_H
#define COMP6771_STATS_H

#include <string>
#include <vector>

struct stats {
    int avg;
    int median;
    int highest;
    int lowest;
};

/**
 * @brief Reads from the file at `path` a list of newline separated numbers.
 * 
 * You can assume the path already leads to a valid file in the correct format with at least one line
 * 
 * @param path The filepath to load.
 * @return std::vector<int> A vector of marks (which are ints)
 */
auto read_marks(const std::string &path) -> std::vector<int>;

/**
 * @brief Calculates the average, median, and highest/lowest mark from a vector of marks.
 * 
 * You can assume the vector always has at least one element.
 * 
 * @param marks The marks to run statistics on
 * @return stats A struct that describes the statistics
 */
auto calculate_stats(const std::vector<int> &marks) -> stats;

#endif // COMP6771_STATS_H