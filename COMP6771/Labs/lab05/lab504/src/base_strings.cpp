#include "./base_strings.h"

#include <algorithm>
#include <bitset>
#include <string>

auto base2str::operator<=>(base2str const& other) const -> const std::strong_ordering {
	return bits <=> other.bits;
}

auto base16str::operator<=>(base16str const& other) const -> const std::strong_ordering {
	return hexits <=> other.hexits;
}

auto base16str::operator<=>(base2str const& other) const -> const std::weak_ordering {
	unsigned long long this_value = std::strtoull(hexits.c_str(), nullptr, 16);
	auto this_bits = std::bitset<128>(this_value);

    auto new_bits = other.bits;
	unsigned long long other_value = std::strtoull(new_bits.erase(0, 2).c_str(), nullptr, 2);
	auto other_bits = std::bitset<128>(other_value);

	return this_bits.to_ullong() <=> other_bits.to_ullong();
}