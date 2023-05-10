#include "word_ladder.h"
#include "word_ladder.cpp"

#include <iostream>

// Please note: it's not good practice to test your code via a main function that does
//  printing. Instead, you should be using your test folder. This file should only really
//  be used for more "primitive" debugging as we know that working solely with test
//  frameworks might be overwhelming for some.

auto main() -> int {
	auto const english_lexicon = word_ladder::read_lexicon("./english.txt");

	// std::string from = "awake";
	// std::string to = "sleep";
	// std::string from = "work";
	// std::string to = "play";
	std::string from = "atlases";
	std::string to = "cabaret";
	// std::string from = "code";
	// std::string to = "data";

	auto const ladders =  word_ladder::generate(from, to, english_lexicon);


	std::cout << "ladders, size: " << ladders.size() << std::endl;
	for (auto const &ladder : ladders) {
		std::cout << "\t{ ";
		for (auto it = ladder.begin(); it != ladder.end() - 1; ++it) {
			std::cout << *it << " -> ";
		}
		std::cout << ladder.back() << " }" << std::endl;
	}
}

