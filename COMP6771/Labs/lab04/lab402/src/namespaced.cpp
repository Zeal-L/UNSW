#include "./namespaced.h"

#include <iostream>

int main() {
    namespace spaceland = comp6771;

    // should be an alias for std::vector.
    auto v = spaceland::vector{6771};

    // name: earth, position from sun: 3
    auto earth = spaceland::planet{"earth", 3};

    // should produce an object with the same type as the "earth" variable above.
    auto old_earth = spaceland::planets::terrestrial{"earth", 3};

    std::cout << v[0] << std::endl;
    std::cout << earth.name << std::endl;
    std::cout << old_earth.pos << std::endl;
}