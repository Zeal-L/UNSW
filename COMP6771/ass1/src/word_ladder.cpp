#include "word_ladder.h"
#include <unordered_map>
#include <algorithm>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <queue>
#include <string>
#include <utility>
#include <vector>

auto word_ladder::read_lexicon(const std::string& path) -> std::unordered_set<std::string> {
	auto file = std::ifstream(path);
	auto lexicon = std::unordered_set<std::string>{};
	std::string word;
	while (std::getline(file, word)) {
		lexicon.emplace(word);
	}
	file.close();
	return lexicon;
}

// This function takes a dictionary with a set of words and a size.
// It returns a vector of strings that contains all the words of the
// given size. If there are no words of the given size, it returns an
// empty vector.
auto get_lexicon_by_size(const std::unordered_set<std::string>& lexicon, std::size_t const word_size)
    -> std::vector<std::string> {
	std::vector<std::string> result;
	for (const auto& word : lexicon) {
		if (word.size() == word_size) {
			result.emplace_back(word);
		}
	}
	return result;
}

// Returns true if the two words differ in only one letter, and false otherwise.
auto is_one_letter_different(std::string const& word1, std::string const& word2) -> bool {
	bool found_difference = false;
	for (auto i = 0u; i < word1.size(); ++i) {
		if (word1[i] != word2[i]) {
			if (found_difference) {
				return false;
			}
			found_difference = true;
		}
	}
	return found_difference;
}

// This code builds a graph of words that are only one letter different from each other.
// The graph is built by iterating over all possible pairs of words and checking if they are one letter different.
// If they are, they are added to the graph as adjacent vertices.
auto build_graph(auto const& words) -> std::unordered_map<std::string, std::unordered_set<std::string>> {
	auto graph = std::unordered_map<std::string, std::unordered_set<std::string>>{};
	for (auto i = 0u; i < words.size(); ++i) {
		for (auto j = i + 1u; j < words.size(); ++j) {
			if (is_one_letter_different(words[i], words[j])) {
				graph[words[i]].emplace(words[j]);
				graph[words[j]].emplace(words[i]);
			}
		}
	}
	return graph;
}

// Backtrack from the current node to the start node recursively, adding the path to the result
auto backtrack(auto const& parent, auto& result, auto& path, auto& current, auto& from) -> void {
	if (current == from) {
		auto temp = path;
		std::reverse(temp.begin(), temp.end());
		result.emplace_back(temp);
		return;
	}
	if (parent.count(current) == 0) return;
	for (const auto& it : parent.at(current)) {
		path.emplace_back(it);
		backtrack(parent, result, path, it, from);
		path.pop_back();
	}
}

auto word_ladder::generate(const std::string& from, const std::string& to, const std::unordered_set<std::string>& lexicon)
    -> std::vector<std::vector<std::string>> {
	// Build graph and create queue
	auto queue = std::queue<std::string>{};
	auto graph = build_graph(get_lexicon_by_size(lexicon, from.size()));

	// Initialize data structures
	auto dist = std::unordered_map<std::string, int>{};
	auto parent = std::unordered_map<std::string, std::unordered_set<std::string>>{};
	dist[from] = 0;
	parent[from].emplace(from);
	queue.push(from);

	auto max_dist = std::numeric_limits<int>::max();

	// BFS
	while (!queue.empty()) {
		auto current = queue.front();
		queue.pop();

		for (const auto& it : graph[current]) {
			if (dist.find(it) == dist.end() || dist[it] > dist[current] + 1) {
				dist[it] = dist[current] + 1;

				// If the distance is less than the maximum distance, we add it to the queue
				if (dist[it] <= max_dist) queue.push(it);

				parent[it].clear();
				parent[it].emplace(current);

				if (it == to) max_dist = dist[it];
			} else if (dist[it] == dist[current] + 1) {
				parent[it].emplace(current);
			}
		}
	}

	// Backtracking
	auto results = std::vector<std::vector<std::string>>{};
	auto temp = std::vector<std::string>{to};
	backtrack(parent, results, temp, to, from);
	std::sort(results.begin(), results.end());
	return results;
}
