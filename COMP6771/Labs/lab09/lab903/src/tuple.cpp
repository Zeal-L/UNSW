#include "./tuple.h"

#include <iostream>

int main() {
    auto t = tuple{1, 'a', 3.14, "$w@G"};

    std::cout << get<0>(t) << std::endl;
    std::cout << get<2>(t) << std::endl;
    std::cout << get<1>(t) << std::endl;
    std::cout << get<3>(t) << std::endl;
}
/**
 * Output:
 * 1
 * 3.14
 * a
 * $w@G
 */
