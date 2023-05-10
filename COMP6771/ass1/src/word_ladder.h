#ifndef COMP6771_WORD_LADDER_H
#define COMP6771_WORD_LADDER_H

#include <unordered_set>
#include <string>
#include <vector>

namespace word_ladder {
	// Given a file path to a newline-separated list of words...
	// Loads those words into an unordered set and returns it.
	auto read_lexicon(const std::string &path) -> std::unordered_set<std::string>;

	// Given a start word and destination word, returns all the shortest possible paths from the
	// start word to the destination, where each word in an individual path is a valid word per the
	// provided lexicon.
	// Preconditions:
	// - from.size() == to.size()
	// - lexicon.contains(from)
	// - lexicon.contains(to)
	auto generate(
		const std::string &from,
		const std::string &to,
	    const std::unordered_set<std::string> &lexicon
	) -> std::vector<std::vector<std::string>>;
} // namespace word_ladder

#endif // COMP6771_WORD_LADDER_H
