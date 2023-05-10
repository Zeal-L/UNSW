#include "stats.h"
#include <fstream>
#include <algorithm>
#include <numeric>

auto read_marks(const std::string &path) -> std::vector<int> {
    std::vector<int> marks;
    auto file = std::ifstream(path);
    std::string temp;
    while (std::getline(file, temp)) {
		marks.push_back(std::stoi(temp));
	}
	file.close();
    return marks;
}

auto calculate_stats(const std::vector<int> &marks) -> stats {
    int avg = std::accumulate(marks.begin(), marks.end(), 0) / static_cast<int>(marks.size());
    auto [lowest, highest] = std::minmax_element(marks.begin(), marks.end());
    auto sorted = marks;
    std::sort(sorted.begin(), sorted.end());
    int median = sorted[sorted.size() / 2];
    return stats{avg, median, *highest, *lowest};
}