#include "./expr.h"

#include <iostream>

int main() {
    std::unique_ptr<expr> expr = std::make_unique<plus>(
        std::make_unique<multiply>(
            std::make_unique<divide>(
                std::make_unique<literal>(2000),
                std::make_unique<literal>(4)
            ),
            std::make_unique<literal>(13)
        ),
        std::make_unique<minus>(
            std::make_unique<literal>(700),
            std::make_unique<plus>(                
                std::make_unique<multiply>(
                    std::make_unique<literal>(60),
                    std::make_unique<literal>(7)
                ),
                std::make_unique<literal>(9)
            )
        )
    );

    std::cout << "COMP" << static_cast<int>(expr->eval()) << ": Advanced C++ Programming\n";
}
/**
 * Output:
 * COMP6771: Advanced C++ Programming
 */
