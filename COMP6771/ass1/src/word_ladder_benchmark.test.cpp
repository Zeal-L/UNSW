#include "word_ladder.h"

#include <catch2/catch.hpp>

TEST_CASE("atlases -> cabaret") {
	auto const english_lexicon = ::word_ladder::read_lexicon("./english.txt");
	auto const ladders = ::word_ladder::generate("atlases", "cabaret", english_lexicon);

	CHECK(std::size(ladders) != 0);
}
