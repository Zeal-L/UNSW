#include "scale.h"

auto scale(std::vector<int>& ivec, double factor) -> std::vector<double> {
    std::vector<double> dvec;
    for (auto i : ivec) {
        dvec.push_back(static_cast<double>(i) * factor);
    }
    return dvec;
}
