#include "./book.h"

#include <catch2/catch.hpp>

TEST_CASE("test book info") {
    auto b = book{"The C++ Programming Language", "Bjarne Stroustrup", "978-0321563842", 59.99};
    CHECK(b.name() == "The C++ Programming Language");
    CHECK(b.author() == "Bjarne Stroustrup");
    CHECK(b.isbn() == "978-0321563842");
    CHECK(b.price() == 59.99);
}

TEST_CASE("test book operator") {
    auto b1 = book{"The C++ Programming Language", "Bjarne Stroustrup", "978-0321563842", 59.99};
    auto b2 = book{"The C++ Programming Language", "Bjarne Stroustrup", "978-0321563842", 59.99};
    auto b3 = book{"The C++ Programming Language", "Bjarne Stroustrup", "978-0321563843", 59.99};
    CHECK(b1 == b2);
    CHECK(b1 != b3);
    CHECK(b1 < b3);
}
TEST_CASE("test type conversion operator") {
    book b = {"Tour of C++11", "Bjarne Stroustrup", "0123456789X", 9000};
    std::string s = static_cast<std::string>(b);
    CHECK(s == "Bjarne Stroustrup, Tour of C++11");
}


TEST_CASE("test book iostream") {
    book b = {"Tour of C++11", "Bjarne Stroustrup", "0123456789X", 9001};
    std::ostringstream oss;
	oss << b;
	CHECK(oss.str() == "Tour of C++11, Bjarne Stroustrup, 0123456789X, $9001.00");
}
