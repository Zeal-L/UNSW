#include "./ring.h"

#include <iostream>
#include <vector>

using namespace std::literals; // for a std::string literal

int main() {
    {
        try {
            auto r1 = ring<int, 2>{1, 2, 3};
        } catch(const std::invalid_argument &e) {
            std::cout << e.what() << std::endl;
        }

        auto r1 = ring{1, 2, 3};
        for (auto i = 0ul, sz = r1.size(); i < sz; ++i) {
            std::cout << r1.peek() << " ";
            r1.pop();
        }
        std::cout << std::endl;

        r1.push(42);
        r1.push(6771);

        for (auto i = 0ul, sz = r1.size(); i < sz; ++i) {
            std::cout << r1.peek() << " ";
            r1.pop();
        }
        std::cout << std::endl;
    }

    {
        auto v = std::vector{"hello"s, "world!"s};
        try {
            auto r2 = ring<std::string, 1>{v.begin(), v.end()};
        } catch(const std::invalid_argument &e) {
            std::cout << e.what() << std::endl;
        }

        auto r2 = ring<std::string, 3>{v.begin(), v.end()};
        for (auto i = 0ul, sz = r2.size(); i < sz; ++i) {
            std::cout << r2.peek() << " ";
            r2.pop();
        }
        std::cout << std::endl;

        r2.push("yet another"s);
        r2.push("lazy sunday"s);

        for (auto i = 0ul, sz = r2.size(); i < sz; ++i) {
            std::cout << r2.peek() << " ";
            r2.pop();
        }
        std::cout << std::endl;
    }

}
/**
 * Output;
 * Not enough capacity
 * 1 2 3
 * 42 6771
 * Not enough capacity
 * hello world!
 * yet another lazy sunday
 */
