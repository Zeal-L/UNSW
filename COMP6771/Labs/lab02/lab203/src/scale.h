#ifndef COMP6771_SCALE_H
#define COMP6771_SCALE_H

#include <vector>

/**
 * Scales a vector of ints, as if by taking each element "e" of the vector and computing e * factor.
 * @param ivec - The vector whose elements to scale
 * @param factor - the factor by which to scale. Defaults to 0.5
 * @return - a new vector of doubles
 */
auto scale(std::vector<int> &ivec, double factor = 0.5) -> std::vector<double>;




#endif // COMP6771_SCALE_H