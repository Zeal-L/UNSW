#ifndef COMP6771_BASE_STRINGS_H
#define COMP6771_BASE_STRINGS_H

#include <compare>
#include <string>

struct base2str;
struct base16str;

struct base2str {
	std::string bits;
	auto operator<=>(base2str const&) const -> const std::strong_ordering;
};

struct base16str {
	std::string hexits;
	auto operator<=>(base16str const&) const -> const std::strong_ordering;
	auto operator<=>(base2str const&) const -> const std::weak_ordering;
};

#endif // COMP6771_BASE_STRINGS_H
