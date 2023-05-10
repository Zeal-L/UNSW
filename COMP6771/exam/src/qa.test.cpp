#include "./qa.h"

#include <catch2/catch.hpp>

#include <iostream>
#include <limits>
#include <typeinfo>

struct double_traits {
	static auto ctor(double a, double b) -> double {
		return a * b;
	}

	static auto null() noexcept -> double {
		// I wonder what could lie beyond... infinity
		return std::numeric_limits<double>::infinity();
		// I'm lost in the pursuit of my... finality
	}

	static auto dtor(double&) noexcept -> void {
		// do nothing -- doubles are trivial
	}
};

auto maybe_get_double() -> maybe<double, double_traits> {
	return maybe<double, double_traits>{1.0, 3.5};
}

TEST_CASE("Sanity check") {
	auto maybe_double = maybe_get_double();
	CHECK(maybe_double == true);
	CHECK(*maybe_double == Approx(3.5));
}

TEST_CASE("null") {
	auto maybe_double = maybe<double, double_traits>{};
	CHECK(maybe_double == false);
	CHECK_THROWS_AS(*maybe_double, std::runtime_error);
}

TEST_CASE("size") {
	auto maybe_double = maybe<double, double_traits>{};

	CHECK(sizeof(maybe_double) == sizeof(double));
}

TEST_CASE("move constructor") {
	auto maybe_double = maybe_get_double();
	auto maybe_double2 = std::move(maybe_double);

	CHECK(maybe_double == false);
	CHECK(maybe_double2 == true);
	CHECK(*maybe_double2 == Approx(3.5));
}

TEST_CASE("move assignment") {
	auto maybe_double = maybe_get_double();
	auto maybe_double2 = maybe<double, double_traits>{};

	maybe_double2 = std::move(maybe_double);

	CHECK(maybe_double == false);
	CHECK(maybe_double2 == true);
	CHECK(*maybe_double2 == Approx(3.5));
}

TEST_CASE("self-move") {
	auto maybe_double = maybe_get_double();
	auto& maybe_double_ref = maybe_double;

	maybe_double = std::move(maybe_double_ref);

	CHECK(maybe_double == true);
	CHECK(*maybe_double == Approx(3.5));
}

TEST_CASE("type") {
	CHECK(std::is_same_v<remove_array_ref_t<int>, int>);
	CHECK(std::is_same_v<remove_array_ref_t<int[]>, int>);
	CHECK(std::is_same_v<remove_array_ref_t<int[3]>, int>);
	CHECK(std::is_same_v<remove_array_ref_t<int[3][3]>, int>);
	CHECK(std::is_same_v<remove_array_ref_t<int[3][3][3]>, int>);
	CHECK(std::is_same_v<remove_array_ref_t<int&&>, int>);
	CHECK(std::is_same_v<remove_array_ref_t<int(&)[]>, int>);
	CHECK(std::is_same_v<remove_array_ref_t<int(&)[3]>, int>);
	CHECK(std::is_same_v<remove_array_ref_t<int(&)[3][3]>, int>);
	CHECK(std::is_same_v<remove_array_ref_t<int(&)[3][3][3]>, int>);
}

TEST_CASE("empty equality") {
	auto maybe_double = maybe<double, double_traits>{};
	auto maybe_double2 = maybe<double, double_traits>{};

	CHECK(maybe_double == maybe_double2);
}

TEST_CASE("equality") {
	auto maybe_double = maybe_get_double();
	auto maybe_double2 = maybe_get_double();

	CHECK(maybe_double == maybe_double2);
}

TEST_CASE("inequality") {
	auto maybe_double = maybe_get_double();
	auto maybe_double2 = maybe<double, double_traits>{};

	CHECK(maybe_double != maybe_double2);
}

struct int_traits {
	static auto ctor(int a, int b) -> int {
		return a * b;
	}

	static auto null() noexcept -> int {
		return std::numeric_limits<int>::infinity();
	}

	static auto dtor(int&) noexcept -> void {
		// do nothing -- ints are trivial
	}
};

auto maybe_get_int() -> maybe<int, int_traits> {
	return maybe<int, int_traits>{3, 3};
}

TEST_CASE("Sanity check int") {
	auto maybe_int = maybe_get_int();
	CHECK(maybe_int == true);
	CHECK(*maybe_int == 9);
}

TEST_CASE("null int") {
	auto maybe_int = maybe<int, int_traits>{};
	CHECK(maybe_int == false);
	CHECK_THROWS_AS(*maybe_int, std::runtime_error);
}

struct int_array_traits {
	static auto ctor(int (&arr)[]) -> int {
		return arr[0];
	}

	static auto null() noexcept -> int {
		return std::numeric_limits<int>::infinity();
	}

	static auto dtor(int&) noexcept -> void {
		// do nothing -- ints are trivial
	}
};

auto maybe_get_int_array() -> maybe<int(&)[6771], int_array_traits> {
	static int arr[6771] = {1, 2, 3, 4, 5};
	return maybe<int(&)[6771], int_array_traits>{arr};
}

TEST_CASE("Sanity check int array") {
	auto maybe_int_array = maybe_get_int_array();
	CHECK(maybe_int_array == true);
	CHECK(*maybe_int_array == 1);
}
