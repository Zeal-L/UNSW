#include "./matrix.h"

#include <catch2/catch.hpp>

TEST_CASE("test constructor") {
	matrix m1;
	CHECK(m1.dimensions().first == 0);
	CHECK(m1.dimensions().second == 0);
}

TEST_CASE("test constructor with initializer_list") {
	matrix m1{{1, 2, 3}, {4, 5, 6}};
	CHECK(m1.dimensions() == std::make_pair<std::size_t, std::size_t>(2, 3));

	CHECK(m1(0, 0) == 1);
	CHECK(m1(0, 1) == 2);
	CHECK(m1(0, 2) == 3);
	CHECK(m1(1, 0) == 4);
	CHECK(m1(1, 1) == 5);
	CHECK(m1(1, 2) == 6);
}

TEST_CASE("test constructor with initializer_list - exception") {
	CHECK_THROWS_MATCHES(matrix({{1, 2, 3}, {4, 5}}),
	                     std::logic_error,
	                     Catch::Matchers::Message("Columns are not equal length"));
}

TEST_CASE("test copy constructor") {
	matrix m1{{1, 2, 3}, {4, 5, 6}};
	matrix m2{m1};
	CHECK(m1 == m2);
}

TEST_CASE("test move constructor") {
	matrix m1{{1, 2, 3}, {4, 5, 6}};
	matrix m2{std::move(m1)};
	CHECK(m1.dimensions() == std::make_pair<std::size_t, std::size_t>(0, 0));
}

TEST_CASE("test copy assignment") {
	matrix m1{{1, 2, 3}, {4, 5, 6}};
	matrix m2;
	m2 = m1;
	CHECK(m1 == m2);
}

TEST_CASE("test move assignment") {
	matrix m1{{1, 2, 3}, {4, 5, 6}};
	matrix m2;
	m2 = std::move(m1);
	CHECK(m1.dimensions() == std::make_pair<std::size_t, std::size_t>(0, 0));
}

TEST_CASE("test get element - invalid") {
	matrix m1{{1, 2, 3}, {4, 5, 6}};
	CHECK_THROWS_MATCHES(m1(2, 0), std::domain_error, Catch::Matchers::Message("(2, 0) does not fit within a matrix with dimensions (2, 3)"));
}

TEST_CASE("test data()") {
	matrix m1{{1, 2, 3}, {4, 5, 6}};
	CHECK(m1.data() == &m1(0, 0));
}