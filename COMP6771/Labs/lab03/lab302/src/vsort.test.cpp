#include "vsort.h"

#include <catch2/catch.hpp>

TEST_CASE("vowel sort single letter") {
	auto vs = std::vector<std::string>{"a", "b", "c", "d", "e", "f", "g", "h"};
	vsort(vs);
	CHECK(vs == std::vector<std::string>{"a", "e", "b", "c", "d", "f", "g", "h"});
}

TEST_CASE("vowel sort multiple letters") {
	auto vs = std::vector<std::string>{"aa", "bb", "cc", "dd", "ee", "ff", "gg", "hh"};
	vsort(vs);
	CHECK(vs == std::vector<std::string>{"aa", "ee", "bb", "cc", "dd", "ff", "gg", "hh"});
}

TEST_CASE("vowel sort one word") {
	auto vs = std::vector<std::string>{"apple", "banana", "carrot", "date", "egg", "fig", "grape", "honey"};
	vsort(vs);
	CHECK(vs == std::vector<std::string>{"banana", "apple", "carrot", "date", "grape", "honey", "egg", "fig"});
}

TEST_CASE("vowel sort with capital letter") {
	auto vs = std::vector<std::string>{"Apple", "banana", "carrot", "date", "egg", "fig", "grape", "honey"};
	vsort(vs);
	CHECK(vs == std::vector<std::string>{"banana", "Apple", "carrot", "date", "grape", "honey", "egg", "fig"});
}