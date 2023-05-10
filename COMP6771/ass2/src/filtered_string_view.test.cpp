#include "./filtered_string_view.h"

#include <catch2/catch.hpp>
#include <iostream>
#include <set>

#include <cstring>
#include <iostream>
#include <sstream>
#include <vector>

using namespace fsv;

//? //////////////////////////////////////////////
//  Test - Constructor
//? //////////////////////////////////////////////

TEST_CASE("Default Constructor") {
	auto sv = filtered_string_view{};
	CHECK(sv.empty());
	CHECK(sv.predicate()('a'));
}

TEST_CASE("Implicit String Constructor") {
	auto s = std::string{"cat"};
	auto sv = filtered_string_view{s};
	CHECK(sv.size() == 3);
}

TEST_CASE("String Constructor with Predicate") {
	auto s = std::string{"cat"};
	auto pred = [](const char& c) { return c == 'a'; };
	auto sv = filtered_string_view{s, pred};

	CHECK(sv.size() == 1);
}

TEST_CASE("Implicit Null-Terminated String Constructor") {
	auto sv = filtered_string_view{"cat"};
	CHECK(sv.size() == 3);
}

TEST_CASE("Null-Terminated String with Predicate Constructor") {
	auto pred = [](const char& c) { return c == 'a'; };
	auto sv = filtered_string_view{"cat", pred};
	CHECK(sv.size() == 1);
}

TEST_CASE("Copy and Move Constructors") {
	auto sv1 = filtered_string_view{"bulldog"};
	const auto copy = sv1;
	CHECK(copy.data() == sv1.data());

	const auto move = std::move(sv1);
	CHECK(sv1.data() == nullptr);
}

//? //////////////////////////////////////////////
//  Test - Member Operators
//? //////////////////////////////////////////////

TEST_CASE("Copy Assignment") {
	auto pred = [](const char& c) { return c == '4' || c == '2'; };
	auto fsv1 = filtered_string_view{"42 bro", pred};
	auto fsv2 = filtered_string_view{};
	fsv2 = fsv1;

	CHECK(fsv1 == fsv2);
}

TEST_CASE("Move Assignment") {
	auto pred = [](const char& c) { return c == '8' || c == '9'; };
	auto fsv1 = filtered_string_view{"'89 baby", pred};
	auto fsv2 = filtered_string_view{};
	fsv2 = std::move(fsv1);

	CHECK(fsv1.empty());
	CHECK(fsv1.data() == nullptr);
	CHECK(fsv2.size() == 2);
	CHECK(fsv2 == "89");
}

TEST_CASE("Subscript") {
	auto pred = [](const char& c) { return c == '9' || c == '0' || c == ' '; };
	SECTION("Subscript - number") {
		auto fsv1 = filtered_string_view{"1234567890123456", pred};
		CHECK(fsv1[1] == '0');
	}

	SECTION("Subscript - large") {
		auto fsv1 = filtered_string_view{"only 90s kids understand", pred};
		CHECK(fsv1[2] == '0');
	}
}

TEST_CASE("String Type Conversion") {
	auto sv = filtered_string_view("vizsla");
	auto s = static_cast<std::string>(sv);
	s = "aaa";
	CHECK(sv.data() != s.data());
}

//? //////////////////////////////////////////////
//  Test - Member Functions
//? //////////////////////////////////////////////

TEST_CASE("at") {
	SECTION("at - normal") {
		auto vowels = std::set<char>{'a', 'A', 'e', 'E', 'i', 'I', 'o', 'O', 'u', 'U'};
		auto is_vowel = [&vowels](const char& c) { return vowels.contains(c); };
		auto sv = filtered_string_view{"Malamute", is_vowel};
		CHECK(sv.size() == 4);
		CHECK(sv.at(0) == 'a');
		CHECK(sv.at(1) == 'a');
		CHECK(sv.at(2) == 'u');
		CHECK(sv.at(3) == 'e');
	}

	SECTION("at - invalid index") {
		auto sv = filtered_string_view{""};
		CHECK_THROWS_MATCHES(sv.at(0),
		                     std::domain_error,
		                     Catch::Matchers::Message("filtered_string_view::at(0): invalid index"));
		CHECK_THROWS_MATCHES(sv.at(-5),
		                     std::domain_error,
		                     Catch::Matchers::Message("filtered_string_view::at(-5): invalid index"));
		CHECK_THROWS_MATCHES(sv.at(50),
		                     std::domain_error,
		                     Catch::Matchers::Message("filtered_string_view::at(50): invalid index"));
	}
}

TEST_CASE("size") {
	SECTION("size - normal") {
		auto sv = filtered_string_view{"Maltese"};
		CHECK(sv.size() == 7);
	}

	SECTION("size - with predicate") {
		auto sv = filtered_string_view{"Toy Poodle", [](const char& c) { return c == 'o'; }};
		CHECK(sv.size() == 3);
	}
}

TEST_CASE("empty") {
	SECTION("empty - normal") {
		auto sv = filtered_string_view{"Australian Shephard"};
		auto empty_sv = filtered_string_view{};
		CHECK(!sv.empty());
		CHECK(empty_sv.empty());
	}

	SECTION("empty - with predicate") {
		auto sv = filtered_string_view{"Border Collie", [](const char& c) { return c == 'z'; }};
		CHECK(sv.empty());
	}
}

TEST_CASE("data") {
	auto s = "Sum 42";
	SECTION("data - normal") {
		auto sv = filtered_string_view{s};
		CHECK(sv.data() == s);
		CHECK(std::strcmp(sv.data(), s) == 0);
	}
	SECTION("data - with predicate") {
		auto sv = filtered_string_view{s, [](const char&) { return false; }};
		CHECK(sv.data() == s);
		CHECK(std::strcmp(sv.data(), s) == 0);
	}
}

TEST_CASE("predicate") {
	const auto print_and_return_true = [](const char& c) { return c == 'o'; };
	const auto s = filtered_string_view{"doggo", print_and_return_true};
	const auto& predicate = s.predicate();
	const auto s2 = filtered_string_view{"doggo", predicate};
	CHECK(s2.size() == 2);
	predicate('o');
}

//? //////////////////////////////////////////////
//  Test - Non-Member Operators
//? //////////////////////////////////////////////

TEST_CASE("Equality Comparison - equal") {
	auto const lo = filtered_string_view{"aaa"};
	CHECK(lo == lo);
}

TEST_CASE("Equality Comparison - not equal") {
	auto const lo = filtered_string_view{"aaa"};
	auto const hi = filtered_string_view{"zzz"};
	CHECK(lo != hi);
}

TEST_CASE("Equality Comparison - different predicate") {
	auto const lo = filtered_string_view{"aaa", [](const char& c) { return c == 'a'; }};
	auto const hi = filtered_string_view{"aaa", [](const char& c) { return c == 'z'; }};
	CHECK(lo != hi);
}

TEST_CASE("Relational Comparison") {
	auto const lo = filtered_string_view{"aaa"};
	auto const hi = filtered_string_view{"zzz"};
	CHECK(lo < hi);
	CHECK(lo <= hi);
	CHECK(hi > lo);
	CHECK(hi >= lo);
}

TEST_CASE("Output Stream") {
	auto fsv = filtered_string_view{"c++ > rust > java", [](const char& c) { return c == 'c' || c == '+'; }};
	std::ostringstream oss;
	oss << fsv;
	CHECK(oss.str() == "c++");
}

//? //////////////////////////////////////////////
//  Test - Non-Member Utility Functions
//? //////////////////////////////////////////////

TEST_CASE("compose") {
	auto best_languages = filtered_string_view{"c / c++"};
	auto vf = std::vector<filter>{[](const char& c) { return c == 'c' || c == '+' || c == '/'; },
	                              [](const char& c) { return c > ' '; },
	                              [](const char&) { return true; }};
	auto sv = fsv::compose(best_languages, vf);

	CHECK(sv.size() == 5);
	CHECK(sv == "c/c++");
}

TEST_CASE("split - spec test ") {
	SECTION("split - spec test 1") {
		auto interest = std::set<char>{'a', 'A', 'b', 'B', 'c', 'C', 'd', 'D', 'e', 'E', 'f', 'F', ' ', '/'};
		auto sv =
		    filtered_string_view{"0xDEADBEEF / 0xdeadbeef", [&interest](const char& c) { return interest.contains(c); }};
		auto tok = filtered_string_view{" / "};
		auto v = fsv::split(sv, tok);
		CHECK(v.size() == 2);
		CHECK(v[0] == "DEADBEEF");
		CHECK(v[1] == "deadbeef");
	}

	SECTION("split - spec test 2") {
		auto sv = fsv::filtered_string_view{"xax"};
		auto tok = fsv::filtered_string_view{"x"};
		auto v = fsv::split(sv, tok);
		auto expected = std::vector<fsv::filtered_string_view>{"", "a", ""};
		CHECK(v.size() == 3);
		CHECK(v == expected);
	}

	SECTION("split - spec test 3") {
		auto sv = fsv::filtered_string_view{"xx"};
		auto tok = fsv::filtered_string_view{"x"};
		auto v = fsv::split(sv, tok);
		auto expected = std::vector<fsv::filtered_string_view>{"", "", ""};
		CHECK(v.size() == 3);
		CHECK(v == expected);
	}
}

TEST_CASE("split - my test") {
	SECTION("split - same two") {
		auto fsv = filtered_string_view{"bAbA"};
		auto tok = filtered_string_view{"A"};
		auto v = fsv::split(fsv, tok);
		CHECK(v.size() == 3);
		CHECK(v[0] == "b");
		CHECK(v[1] == "b");
		CHECK(v[2].empty());
	}

	SECTION("split - empty tok") {
		auto fsv = filtered_string_view{"AA"};
		auto tok = filtered_string_view{""};
		auto v = fsv::split(fsv, tok);
		CHECK(v.size() == 1);
		CHECK(v[0] == "AA");
	}

	SECTION("split - tok not appearing") {
		auto fsv = filtered_string_view{"AA"};
		auto tok = filtered_string_view{"B"};
		auto v = fsv::split(fsv, tok);
		CHECK(v.size() == 1);
		CHECK(v[0] == "AA");
	}

	SECTION("split - underlying string") {
		auto sv = filtered_string_view{"cats are cool"};
		auto tok = filtered_string_view{" are "};
		auto splits = fsv::split(sv, tok);

		CHECK(sv.data() == splits[0].data());
		CHECK(sv.data() == splits[1].data());
		CHECK(splits[0] == "cats");
		CHECK(splits[1] == "cool");
	}

	SECTION("split - a lot") {
		auto fsv = filtered_string_view{"AABABABABABABAA"};
		auto tok = filtered_string_view{"B"};
		auto v = fsv::split(fsv, tok);
		CHECK(v.size() == 7);
		CHECK(v[0] == "AA");
		CHECK(v[3] == "A");
		CHECK(v[6] == "AA");
	}

	SECTION("split - a lot but two valid") {
		auto fsv = filtered_string_view{"AABABABABABABAA"};
		auto tok = filtered_string_view{"BA"};
		auto v = fsv::split(fsv, tok);
		CHECK(v.size() == 7);
		CHECK(v[0] == "AA");
		CHECK(v[3] == "");
		CHECK(v[6] == "A");
	}

	SECTION("split - empty on both sides") {
		auto fsv = filtered_string_view{"token word token"};
		auto tok = filtered_string_view{"token"};
		auto v = fsv::split(fsv, tok);
		CHECK(v.size() == 3);
		CHECK(v[0] == "");
		CHECK(v[1] == " word ");
		CHECK(v[2] == "");
	}
}

TEST_CASE("split - Consecutive separators") {
	SECTION("split - empty") {
		auto fsv = filtered_string_view{"AAAA"};
		auto tok = filtered_string_view{"AA"};
		auto v = fsv::split(fsv, tok);
		CHECK(v.size() == 3);
		CHECK(v[0].empty());
		CHECK(v[1].empty());
		CHECK(v[2].empty());
	}

	SECTION("split - empty - a lot") {
		auto fsv = filtered_string_view{"AAAAAAAA"};
		auto tok = filtered_string_view{"AA"};
		auto v = fsv::split(fsv, tok);
		CHECK(v.size() == 5);
		for (auto& s : v) {
			CHECK(s.empty());
		}
	}

	SECTION("split - empty - on left") {
		auto fsv = filtered_string_view{"AAAAAAB"};
		auto tok = filtered_string_view{"AA"};
		auto v = fsv::split(fsv, tok);
		CHECK(v.size() == 4);
		for (auto i = 0u; i < v.size() - 1; ++i) {
			CHECK(v[i].empty());
		}
		CHECK(v[3] == "B");
	}

	SECTION("split - empty - on right") {
		auto fsv = filtered_string_view{"BAAAAAA"};
		auto tok = filtered_string_view{"AA"};
		auto v = fsv::split(fsv, tok);
		CHECK(v.size() == 4);
		CHECK(v[0] == "B");
		for (auto i = 1u; i < v.size(); ++i) {
			CHECK(v[i].empty());
		}
	}

	SECTION("split - complex") {
		auto fsv = filtered_string_view{",,11,11,11,,,11,,,11,11,11,,,,"};
		auto tok = filtered_string_view{","};
		auto v = fsv::split(fsv, tok);
		auto expected = std::vector<
		    fsv::filtered_string_view>{"", "", "11", "11", "11", "", "", "11", "", "", "11", "11", "11", "", "", "", ""};

		CHECK(v.size() == expected.size());
		CHECK(v == expected);
	}
}

TEST_CASE("substr") {
	SECTION("substr - normal") {
		auto sv = filtered_string_view{"Siberian Husky"};
		auto s = fsv::substr(sv, 9);
		CHECK(s == "Husky");
		CHECK(sv.data() == s.data());
	}
	SECTION("substr - with predicate") {
		auto is_upper = [](const char& c) { return std::isupper(static_cast<unsigned char>(c)); };
		auto sv = filtered_string_view{"Sled Dog", is_upper};
		auto s = fsv::substr(sv, 0, 2);
		CHECK(s == "SD");
		CHECK(sv.data() == s.data());
	}

	SECTION("substr - empty") {
		auto f = [](const char& c) { return c == '?'; };
		auto sv = filtered_string_view{"Siberian Husky", f};
		auto s = fsv::substr(sv);
		CHECK(s == "");
		CHECK(sv.data() == s.data());
	}

	SECTION("substr - with predicate - offset") {
		auto fsv = fsv::filtered_string_view{"abcde", [](const char& c) { return c != 'a'; }};
		auto sv = fsv::substr(fsv, 1, 3);
		CHECK(sv.size() == 3);
		CHECK(static_cast<std::string>(sv) == "cde");
	}
}

//? //////////////////////////////////////////////
//  Test - Iterator
//? //////////////////////////////////////////////

template<typename Container>
concept reversible_container = requires(Container c) {
	                               {
		                               c.begin()
		                               } -> std::same_as<typename Container::iterator>;
	                               {
		                               c.end()
		                               } -> std::same_as<typename Container::iterator>;
	                               {
		                               static_cast<const Container>(c).begin()
		                               } -> std::same_as<typename Container::const_iterator>;
	                               {
		                               static_cast<const Container>(c).end()
		                               } -> std::same_as<typename Container::const_iterator>;
	                               {
		                               c.cbegin()
		                               } -> std::same_as<typename Container::const_iterator>;
	                               {
		                               c.cend()
		                               } -> std::same_as<typename Container::const_iterator>;

	                               {
		                               c.rbegin()
		                               } -> std::same_as<typename Container::reverse_iterator>;
	                               {
		                               c.rend()
		                               } -> std::same_as<typename Container::reverse_iterator>;
	                               {
		                               static_cast<const Container>(c).rbegin()
		                               } -> std::same_as<typename Container::const_reverse_iterator>;
	                               {
		                               static_cast<const Container>(c).rend()
		                               } -> std::same_as<typename Container::const_reverse_iterator>;
	                               {
		                               c.crbegin()
		                               } -> std::same_as<typename Container::const_reverse_iterator>;
	                               {
		                               c.crend()
		                               } -> std::same_as<typename Container::const_reverse_iterator>;
                               };

static_assert(std::bidirectional_iterator<filtered_string_view::iterator>);
static_assert(std::bidirectional_iterator<filtered_string_view::const_iterator>);
static_assert(reversible_container<filtered_string_view>);

TEST_CASE("Iterator - With default predicate") {
	auto expect = std::vector<char>{'c', 'o', 'r', 'g', 'i'};
	auto result = std::vector<char>{};
	auto print_via_iterator = [&result](filtered_string_view const& sv) {
		std::copy(sv.begin(), sv.end(), std::back_inserter(result));
	};
	auto fsv1 = filtered_string_view{"corgi"};
	print_via_iterator(fsv1);
	CHECK(result == expect);
}

TEST_CASE("Iterator - With predicate which removes lowercase vowels") {
	auto fsv = filtered_string_view{"samoyed", [](const char& c) {
		                                return !(c == 'a' || c == 'e' || c == 'i' || c == 'o' || c == 'u');
	                                }};
	auto it = fsv.begin();
	CHECK(*it == 's');
	CHECK(*std::next(it) == 'm');
	CHECK(*std::next(it, 2) == 'y');
	CHECK(*std::next(it, 3) == 'd');
}

TEST_CASE("Iterator - use *x++") {
	auto fsv = filtered_string_view{"abcd"};
	auto it = fsv.begin();
	CHECK(*it++ == 'a');
	CHECK(*it++ == 'b');
	CHECK(*it++ == 'c');
	CHECK(*it == 'd');
}

TEST_CASE("Iterator - use *++x") {
	auto fsv = filtered_string_view{"abcd"};
	auto it = fsv.begin();
	CHECK(*it == 'a');
	CHECK(*++it == 'b');
	CHECK(*++it == 'c');
	CHECK(*++it == 'd');
}

TEST_CASE("Iterator - use *x--") {
	auto fsv = filtered_string_view{"abcd"};
	auto it = fsv.end();
	*it--;
	CHECK(*it-- == 'd');
	CHECK(*it-- == 'c');
	CHECK(*it-- == 'b');
	CHECK(*it == 'a');
}

TEST_CASE("Iterator - use *--x") {
	auto fsv = filtered_string_view{"abcd"};
	auto it = fsv.end();
	CHECK(*--it == 'd');
	CHECK(*--it == 'c');
	CHECK(*--it == 'b');
	CHECK(*--it == 'a');
}

TEST_CASE("Iterator - cend") {
	const auto str = std::string("tosa");
	const auto s = filtered_string_view{str};
	auto it = s.cend();
	CHECK(*std::prev(it) == 'a');
	CHECK(*std::prev(it, 2) == 's');
}

TEST_CASE("Iterator - begin and end") {
	const auto s = filtered_string_view{"puppy", [](const char& c) { return !(c == 'u' || c == 'y'); }};
	auto v = std::vector<char>{s.begin(), s.end()};
	CHECK(v.size() == 3);
	CHECK(v[0] == 'p');
	CHECK(v[1] == 'p');
	CHECK(v[2] == 'p');
}

TEST_CASE("Iterator - rbegin and rend") {
	auto s = filtered_string_view{"milo", [](const char& c) { return !(c == 'i' || c == 'o'); }};
	auto v = std::vector<char>{s.rbegin(), s.rend()};

	CHECK(v[0] == 'l');
	CHECK(v[1] == 'm');
}

TEST_CASE("Iterator - Equality Comparison - not equal") {
	auto str = std::string{"aaa"};
	auto const lo = filtered_string_view{str, [](const char& c) { return c == 'a'; }};
	auto const hi = filtered_string_view{str, [](const char& c) { return c == 'z'; }};

	CHECK(lo.begin() != hi.begin());
	CHECK(lo.end() != hi.end());
}

TEST_CASE("Iterator - Equality Comparison - equal") {
	auto str = std::string{"aaa"};
	auto f = [](const char& c) { return c == 'a'; };
	auto const lo = filtered_string_view{str, f};
	auto const hi = filtered_string_view{str, f};

	CHECK(lo.begin() == hi.begin());
	CHECK(lo.end() == hi.end());
	CHECK(*lo.crbegin() == 'a');
	CHECK(*hi.crbegin() == 'a');
}

TEST_CASE("Iterator - for loop") {
	auto fsv1 = fsv::filtered_string_view{"abcdae", [](const char& c) { return c == 'a'; }};
	auto v1 = std::vector<char>{'a', 'a'};
	std::size_t i = 0;
	for (auto it = fsv1.begin(); it != fsv1.end(); ++it, ++i) {
		CHECK(*it == v1[i]);
	}
}

TEST_CASE("Iterator - for loop - second empty") {
	auto fsv1 = fsv::filtered_string_view{"abcd", [](const char& c) { return c == 'a'; }};
	auto v1 = std::vector<char>{'a', '\0'};
	std::size_t i = 0;
	for (auto it = fsv1.begin(); it != fsv1.end(); ++it, ++i) {
		CHECK(*it == v1[i]);
	}
	CHECK(*++fsv1.begin() == v1[1]);
}

TEST_CASE("Iterator - for loop - empty - filter first") {
	auto fsv1 = fsv::filtered_string_view{"bacb", [](const char& c) { return c == 'a'; }};
	auto v1 = std::vector<char>{'a', '\0'};
	std::size_t i = 0;
	for (auto it = fsv1.begin(); it != fsv1.end(); ++it, ++i) {
		CHECK(*it == v1[i]);
	}
}

TEST_CASE("Iterator - for loop - reverse") {
	auto fsv1 = fsv::filtered_string_view{"abcdae", [](const char& c) { return c == 'a'; }};
	auto v1 = std::vector<char>{'a', 'a'};
	std::size_t i = 0;
	for (auto it = fsv1.rbegin(); it != fsv1.rend(); ++it, ++i) {
		CHECK(*it == v1[i]);
	}
}

TEST_CASE("Iterator - for loop - second empty - reverse") {
	auto fsv1 = fsv::filtered_string_view{"dbca", [](const char& c) { return c == 'a'; }};
	auto v1 = std::vector<char>{'a', '\0'};
	std::size_t i = 0;
	for (auto it = fsv1.rbegin(); it != fsv1.rend(); ++it, ++i) {
		CHECK(*it == v1[i]);
	}
	CHECK(*++fsv1.begin() == v1[1]);
}

TEST_CASE("Iterator - for loop - empty - filter first - reverse") {
	auto fsv1 = fsv::filtered_string_view{"bcab", [](const char& c) { return c == 'a'; }};
	auto v1 = std::vector<char>{'a', '\0'};
	std::size_t i = 0;
	for (auto it = fsv1.rbegin(); it != fsv1.rend(); ++it, ++i) {
		CHECK(*it == v1[i]);
	}
}
