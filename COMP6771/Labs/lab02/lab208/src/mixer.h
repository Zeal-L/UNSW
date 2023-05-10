#ifndef COMP6771_MIXER_H
#define COMP6771_MIXER_H

#include <functional>
#include <optional>
#include <vector>

// all enum members should be in SCREAM_CASE
enum paint {
    RED = 0,
    GREEN = 1,
    BLUE = 2,
    YELLOW = 3,
    CYAN = 4,
    MAGENTA = 5,
    BROWN = 6
};

using mixer_fn = std::optional<paint>(paint, paint);

/**
* Mixes colours according to the below rules.
* red + green = yellow
* red + blue = magenta
* green + blue = cyan
* yellow + magenta = brown
* yellow + cyan = brown
* cyan + magenta = brown
* brown + brown = brown
* otherwise, no combintion
*
* NOTE: red + green != green + red! the order is important (that's why it's wacky!)
*/
auto wacky_colour(paint p1, paint p2) -> std::optional<paint>;

/**
 * Mixes the paints according to a given strategy.
 * This function works by successfully mixing adjacent elements in the vector.
 * For example, if the vector had N > 2 paints...
 * First mix v[0] and v[1] to make a new colour c1
 * Then mix v[2] and c1 to make c2
 * Then mix v[3] and c2 to make c3.
 * And so on.
 * Note: the vector will always have at least 2 paints in it.
 *
 * If a specific colour combination does not exist at any point in the chain of mixing,
 * returns an empty optional<paint>.
 *
 * @param paints - A vector of paints to mix
 * @param fn - the mixing strategy. A function that accepts two colours at a time and returns either a new colour, or no colour at all.
 * @return - An optional paint denoting the mixed colour or nothing if there was no combination
 */
auto mix(const std::vector<paint> &paints, std::function<mixer_fn> fn = wacky_colour) -> std::optional<paint>;

#endif // COMP6771_MIXER_H