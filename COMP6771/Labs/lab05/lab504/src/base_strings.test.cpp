#include "./base_strings.h"

#include <catch2/catch.hpp>

#include <compare>

TEST_CASE("normal comparison") {
	auto bstr = base2str{{"0b1101001110011"}};
	auto hstr = base16str{{"0xdeadbeef"}};

	CHECK(bstr <=> hstr == std::weak_ordering::less);
	CHECK(hstr <=> bstr == std::weak_ordering::greater);
	CHECK(bstr <=> bstr == std::strong_ordering::equal);
	CHECK(hstr <=> hstr == std::strong_ordering::equal);
}

TEST_CASE("different base2str") {
    auto bstr1 = base2str{{"0b1101001110011"}};
    auto bstr2 = base2str{{"0b1101001110010"}};

    CHECK(bstr1 <=> bstr2 == std::weak_ordering::greater);
    CHECK(bstr2 <=> bstr1 == std::weak_ordering::less);
    CHECK(bstr1 <=> bstr1 == std::strong_ordering::equal);
    CHECK(bstr2 <=> bstr2 == std::strong_ordering::equal);
}

TEST_CASE("different base16str") {
    auto hstr1 = base16str{{"0x12345678"}};
    auto hstr2 = base16str{{"0x87654321"}};

    CHECK(hstr1 <=> hstr2 == std::weak_ordering::less);
    CHECK(hstr2 <=> hstr1 == std::weak_ordering::greater);
    CHECK(hstr1 <=> hstr1 == std::strong_ordering::equal);
    CHECK(hstr2 <=> hstr2 == std::strong_ordering::equal);
}

TEST_CASE("equivalent") {
    auto bstr1 = base2str{{"0b1101001110011"}};
    auto bstr2 = base16str{{"0x1a73"}};

    CHECK(bstr1 <=> bstr2 == std::weak_ordering::equivalent);
    CHECK(bstr2 <=> bstr1 == std::weak_ordering::equivalent);
}

