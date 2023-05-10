#include "./rethrow.h"

#include <iostream>
#include <utility>
#include <vector>

int main() {
    auto db = db_conn{};
    const auto attempts = std::vector<std::pair<std::string, std::string>> {
        {"hsmith", "swagger/10"},
        {"vegeta", "over9000"},
        {"billgates", "apple<3"},
        {"billgates", "macros0ft"},
        {"billgates", "m1cros0ft"},
    };
    for (const auto &[uname, pwd] : attempts) {
        try {
        make_connection(db, uname, pwd);
        } catch (const std::string &e) {
            std::cout << "Could not establish connection: " << e << std::endl;
        }
    }
}

/**
 * Output:
 * Could not establish connection: hsmith is not allowed to login.
 * Could not establish connection: HeLp ;_; c0mpu73R c@ann0T c0mPut3 0w0
 * Could not establish connection: HeLp ;_; c0mpu73R c@ann0T c0mPut3 0w0
 */
