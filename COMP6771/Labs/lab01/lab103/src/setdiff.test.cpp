#include "setdiff.h"

#include <catch2/catch.hpp>

TEST_CASE("set_difference_empty()") {
    SECTION("empty set") {
        std::vector<char> vec_set;
        const std::vector<char> blacklist = {'a', 'b', 'c'};
        set_difference(vec_set, blacklist);
        REQUIRE(vec_set.empty());
    }


    SECTION("empty blacklist") {
        std::vector<char> vec_set = {'a', 'b', 'c'};
        const std::vector<char> blacklist;
        set_difference(vec_set, blacklist);
        REQUIRE(vec_set == std::vector<char>({'a', 'b', 'c'}));
    }

    SECTION("no elements in set") {
        std::vector<char> vec_set = {'a', 'b', 'c'};
        const std::vector<char> blacklist = {'a', 'b', 'c'};
        set_difference(vec_set, blacklist);
        REQUIRE(vec_set.empty());
    }
}

TEST_CASE("set_difference_normal()") {
    SECTION("all elements in set") {
        std::vector<char> vec_set = {'a', 'b', 'c'};
        const std::vector<char> blacklist = {'d', 'e', 'f'};
        set_difference(vec_set, blacklist);
        REQUIRE(vec_set == std::vector<char>({'a', 'b', 'c'}));
    }

    SECTION("some elements in set") {
        std::vector<char> vec_set = {'a', 'b', 'c'};
        const std::vector<char> blacklist = {'b', 'd', 'f'};
        set_difference(vec_set, blacklist);
        REQUIRE(vec_set == std::vector<char>({'a', 'c'}));
    }
}

TEST_CASE("set_difference_complex()") {
    SECTION("blacklist duplicates") {
        std::vector<char> vec_set = {'a', 'b', 'c'};
        const std::vector<char> blacklist = {'d', 'f', 'b', 'b', 'b', 'b'};
        set_difference(vec_set, blacklist);
        REQUIRE(vec_set == std::vector<char>({'a', 'c'}));
    }

    SECTION("set duplicates") {
        std::vector<char> vec_set = {'c', 'c', 'c', 'c', 'b', 'a', 'b'};
        const std::vector<char> blacklist = {'c'};
        set_difference(vec_set, blacklist);
        REQUIRE(vec_set == std::vector<char>({'b', 'a', 'b'}));
    }

}