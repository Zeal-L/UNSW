#include "./order.h"

#include <iostream>

int main() {
    {
        D d; A a; B b;
        std::cout << std::endl;
    }
    std::cout << std::endl;
}

/**
 * Output:
 * AAABCABAAABCADAAAB
 * ~B~A~A~A~D~A~C~B~A~A~A~B~A~C~B~A~A~A
 */
