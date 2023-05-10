#include "vsort.h"
#include <algorithm>

auto vsort(std::vector<std::string> &vs) -> void {
	auto vowel = std::string{"aeiouAEIOU"};
	std::sort(vs.begin(), vs.end(), [&vowel](const auto& a, const auto& b) {
		auto a_vowel = std::count_if(a.begin(), a.end(), [&vowel](const auto& c) {
			return vowel.find(c) != std::string::npos;
		});
		auto b_vowel = std::count_if(b.begin(), b.end(), [&vowel](const auto& c) {
			return vowel.find(c) != std::string::npos;
		});
		if (a_vowel != b_vowel) {
			return a_vowel > b_vowel;
		}
		return a < b;
	});
}