#include "assortment.h"
#include "algorithm"

auto sort(std::vector<int> &ivec) -> void {
    std::sort(ivec.begin(), ivec.end());
}

auto sort(std::array<int, 4> &iarr) -> void {
    std::sort(iarr.begin(), iarr.end());
}

auto sort(std::list<int> &ilist) -> void {
    ilist.sort();
}