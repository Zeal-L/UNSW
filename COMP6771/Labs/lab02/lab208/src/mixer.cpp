#include "mixer.h"

auto wacky_colour(paint p1, paint p2) -> std::optional<paint> {
    if (p1 == paint::RED && p2 == paint::GREEN) {
        return paint::YELLOW;
    } else if (p1 == paint::RED && p2 == paint::BLUE) {
        return paint::MAGENTA;
    } else if (p1 == paint::GREEN && p2 == paint::BLUE) {
        return paint::CYAN;
    } else if (p1 == paint::YELLOW && p2 == paint::MAGENTA) {
        return paint::BROWN;
    } else if (p1 == paint::YELLOW && p2 == paint::CYAN) {
        return paint::BROWN;
    } else if (p1 == paint::CYAN && p2 == paint::MAGENTA) {
        return paint::BROWN;
    } else if (p1 == paint::BROWN && p2 == paint::BROWN) {
        return paint::BROWN;
    } else {
        return std::nullopt;
    }
}

auto mix(const std::vector<paint> &paints, std::function<std::optional<paint>(paint, paint)> fn) -> std::optional<paint> {
    if (paints.size() == 0) {
        return std::nullopt;
    } else if (paints.size() == 1) {
        return std::nullopt;
    } else {
        std::optional<paint> result = fn(paints[0], paints[1]);
        for (std::vector<paint>::size_type i = 2; i < paints.size(); i++) {
            result = fn(result.value(), paints[i]);
            if (result == std::nullopt) {
                return std::nullopt;
            }
        }
        return result;
    }
}
