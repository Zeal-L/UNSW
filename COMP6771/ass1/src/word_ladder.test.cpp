#include "word_ladder.h"

#include <catch2/catch.hpp>

TEST_CASE("word_ladder::read_lexicon works as expected") {
	auto const lexicon = word_ladder::read_lexicon("./english.txt");
	CHECK(lexicon.size() == 127142);
	CHECK(lexicon.contains("mama"));
	CHECK(lexicon.contains("zyzzyvas"));
}

TEST_CASE("No Solution: No Path Found") {
	auto const lexicon = std::unordered_set<std::string>{"awake",
	                                                     "aware",
	                                                     "sware",
	                                                     "share",
	                                                     "sharn",
	                                                     "shawn",
	                                                     "shewn",
	                                                     "sheen",
	                                                     "sheep",
	                                                     "shire",
	                                                     "shirr",
	                                                     "shier",
	                                                     "sheer",
	                                                     "sweer"};

	auto const ladders = word_ladder::generate("awake", "sleep", lexicon);
	CHECK(ladders.empty());
}

TEST_CASE("No Solution: Empty Lexicon") {
	auto const lexicon = std::unordered_set<std::string>{};
	auto const ladders = word_ladder::generate("awake", "sleep", lexicon);

	CHECK(ladders.empty());
}

TEST_CASE("No Solution: One word lexicon") {
	auto const lexicon = std::unordered_set<std::string>{"awake"};
	auto const ladders = word_ladder::generate("awake", "sleep", lexicon);

	CHECK(ladders.empty());
}

TEST_CASE("One Solution: at -> it") {
	auto const lexicon = std::unordered_set<std::string>{"at", "it", "da", "ti"};
	const auto expected = std::vector<std::vector<std::string>>{{"at", "it"}};
	auto const ladders = word_ladder::generate("at", "it", lexicon);

	CHECK(ladders == expected);
}

TEST_CASE("One Solution: aware -> sheep") {
	auto const lexicon = std::unordered_set<std::string>{"awake",
	                                                     "aware",
	                                                     "sware",
	                                                     "share",
	                                                     "sharn",
	                                                     "shawn",
	                                                     "shewn",
	                                                     "sheen",
	                                                     "sheep",
	                                                     "shirr",
	                                                     "shier",
	                                                     "sheer"};

	const auto expected =
	    std::vector<std::vector<std::string>>{{"aware", "sware", "share", "sharn", "shawn", "shewn", "sheen", "sheep"}};
	auto const ladders = word_ladder::generate("aware", "sheep", lexicon);

	CHECK(ladders == expected);
}

TEST_CASE("circle case") {
	auto const lexicon = std::unordered_set<std::string>{"abc", "abd", "abe", "abf", "abg", "abh", "cca", "aba", "cba"};
	const auto expected = std::vector<std::vector<std::string>>{{"abc", "aba", "cba"}};
	auto const ladders = word_ladder::generate("abc", "cba", lexicon);

	CHECK(ladders == expected);
}

TEST_CASE("circle case 2") {
	auto const lexicon = std::unordered_set<std::string>{"cat", "cot", "cog", "con", "bog", "bat", "cad", "aba", "cba"};
	const auto expected = std::vector<std::vector<std::string>>{{"cat", "cot", "cog", "bog"}};
	auto const ladders = word_ladder::generate("cat", "bog", lexicon);

	CHECK(ladders == expected);
}

TEST_CASE("circle case 3") {
	auto const lexicon = std::unordered_set<std::string>{"cat", "cot", "cog", "con", "bog", "bat", "cad", "aba", "cba"};
	const auto expected = std::vector<std::vector<std::string>>{{"cad", "cat", "cot", "cog", "bog"}};
	auto const ladders = word_ladder::generate("cad", "bog", lexicon);

	CHECK(ladders == expected);
}

TEST_CASE("Multiple Solution: work -> play") {
	auto const lexicon = std::unordered_set<std::string>{
	    "fork", "foam", "pean", "peak", "perk", "pork", "word", "wood", "pood", "plod", "ploy",
	    "worm", "form", "flam", "flay", "worn", "porn", "pirn", "pian", "plan", "bort", "boat",
	    "blat", "port", "work", "wort", "wert", "pert", "peat", "plat", "play", "paan", "borh"};
	const auto expected = std::vector<std::vector<std::string>>{
	    {"work", "fork", "form", "foam", "flam", "flay", "play"},
	    {"work", "pork", "perk", "peak", "pean", "plan", "play"},
	    {"work", "pork", "perk", "peak", "peat", "plat", "play"},
	    {"work", "pork", "perk", "pert", "peat", "plat", "play"},
	    {"work", "pork", "porn", "pirn", "pian", "plan", "play"},
	    {"work", "pork", "port", "pert", "peat", "plat", "play"},
	    {"work", "word", "wood", "pood", "plod", "ploy", "play"},
	    {"work", "worm", "form", "foam", "flam", "flay", "play"},
	    {"work", "worn", "porn", "pirn", "pian", "plan", "play"},
	    {"work", "wort", "bort", "boat", "blat", "plat", "play"},
	    {"work", "wort", "port", "pert", "peat", "plat", "play"},
	    {"work", "wort", "wert", "pert", "peat", "plat", "play"},
	};
	auto const ladders = word_ladder::generate("work", "play", lexicon);

	CHECK(ladders == expected);
}

TEST_CASE("Multiple Solution: is backward same?: play -> work") {
	auto const lexicon = std::unordered_set<std::string>{
	    "fork", "foam", "pean", "peak", "perk", "pork", "word", "wood", "pood", "plod", "ploy",
	    "worm", "form", "flam", "flay", "worn", "porn", "pirn", "pian", "plan", "bort", "boat",
	    "blat", "port", "work", "wort", "wert", "pert", "peat", "plat", "play", "paan", "borh"};
	const auto expected =
	    std::vector<std::vector<std::string>>{{{"play", "flay", "flam", "foam", "form", "fork", "work"},
	                                           {"play", "flay", "flam", "foam", "form", "worm", "work"},
	                                           {"play", "plan", "pean", "peak", "perk", "pork", "work"},
	                                           {"play", "plan", "pian", "pirn", "porn", "pork", "work"},
	                                           {"play", "plan", "pian", "pirn", "porn", "worn", "work"},
	                                           {"play", "plat", "blat", "boat", "bort", "wort", "work"},
	                                           {"play", "plat", "peat", "peak", "perk", "pork", "work"},
	                                           {"play", "plat", "peat", "pert", "perk", "pork", "work"},
	                                           {"play", "plat", "peat", "pert", "port", "pork", "work"},
	                                           {"play", "plat", "peat", "pert", "port", "wort", "work"},
	                                           {"play", "plat", "peat", "pert", "wert", "wort", "work"},
	                                           {"play", "ploy", "plod", "pood", "wood", "word", "work"}}};
	auto const ladders = word_ladder::generate("play", "work", lexicon);

	CHECK(ladders == expected);
}

TEST_CASE("Multiple Solution: awake -> sleep") {
	auto const lexicon = std::unordered_set<std::string>{"awake",
	                                                     "aware",
	                                                     "sware",
	                                                     "share",
	                                                     "sharn",
	                                                     "shawn",
	                                                     "shewn",
	                                                     "sheen",
	                                                     "sheep",
	                                                     "sleep",
	                                                     "shire",
	                                                     "shirr",
	                                                     "shier",
	                                                     "sheer"};
	const auto expected = std::vector<std::vector<std::string>>{
	    {"awake", "aware", "sware", "share", "sharn", "shawn", "shewn", "sheen", "sheep", "sleep"},
	    {"awake", "aware", "sware", "share", "shire", "shirr", "shier", "sheer", "sheep", "sleep"},
	};
	auto const ladders = word_ladder::generate("awake", "sleep", lexicon);

	CHECK(ladders == expected);
}

TEST_CASE("Multiple Solution: is backward same? :sleep -> awake") {
	auto const lexicon = std::unordered_set<std::string>{"awake",
	                                                     "aware",
	                                                     "sware",
	                                                     "share",
	                                                     "sharn",
	                                                     "shawn",
	                                                     "shewn",
	                                                     "sheen",
	                                                     "sheep",
	                                                     "sleep",
	                                                     "shire",
	                                                     "shirr",
	                                                     "shier",
	                                                     "sheer"};
	const auto expected = std::vector<std::vector<std::string>>{
	    {"sleep", "sheep", "sheen", "shewn", "shawn", "sharn", "share", "sware", "aware", "awake"},
	    {"sleep", "sheep", "sheer", "shier", "shirr", "shire", "share", "sware", "aware", "awake"},
	};
	auto const ladders = word_ladder::generate("sleep", "awake", lexicon);

	CHECK(ladders == expected);
}
