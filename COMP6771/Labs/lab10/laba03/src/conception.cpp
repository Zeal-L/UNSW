#include "./conception.h"

#include <concepts>
#include <iostream>
#include <string>

template<typename A>
requires animal<A>
auto animalia(const A &animal) -> void {
    std::cout << animal.cry() << std::endl;
}

template <std::same_as<robot> A>
auto animalia(const A &) {
    std::cout << "robot cry silently" << std::endl;
}

int main() {
    auto a1 = neko();
    auto a2 = dog();
    auto a3 = duck();
    auto a4 = robot();

    animalia(a1);
    animalia(a2);
    animalia(a3);
    animalia(a4);
}
/**
 * Output:
 * nyaa
 * woof
 * quack
 * robot cry silently
 */
