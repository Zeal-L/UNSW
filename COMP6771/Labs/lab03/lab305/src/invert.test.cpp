#include "invert.h"

#include <catch2/catch.hpp>

TEST_CASE("Normal case") {
	auto m = std::map<std::string, int>{{"hi", 42}, {"bob", 6771}};
	auto n = std::map<int, std::string>{{42, "hi"}, {6771, "bob"}};
	REQUIRE(invert(m) == n);
}

TEST_CASE("Empty map") {
	auto m = std::map<std::string, int>{};
	auto n = std::map<int, std::string>{};
	REQUIRE(invert(m) == n);
}

TEST_CASE("Duplicate keys -- same") {
	auto m = std::map<std::string, int>{{"hi", 42}, {"bob", 6771}, {"hi", 42}};
	auto n = std::map<int, std::string>{{42, "hi"}, {6771, "bob"}};
	REQUIRE(invert(m) == n);
}

TEST_CASE("Duplicate keys -- not same") {
	auto m = std::map<std::string, int>{
	    {"a", 6771},
	    {"ab", 6771},
	    {"abc", 6771},
	    {"xyz", 6772},
	};
	auto n = std::map<int, std::string>{
	    {6771, "abc"},
	    {6772, "xyz"},
	};
	REQUIRE(invert(m) == n);
}

TEST_CASE("Duplicate keys -- not same -- backwards") {
	auto m = std::map<std::string, int>{
	    {"abc", 6771},
	    {"ab", 6771},
	    {"a", 6771},
	    {"xyz", 6772},
	};
	auto n = std::map<int, std::string>{
	    {6771, "abc"},
	    {6772, "xyz"},
	};
	REQUIRE(invert(m) == n);
}