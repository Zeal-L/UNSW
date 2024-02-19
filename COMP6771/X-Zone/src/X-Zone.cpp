#include "X-Zone.h"
using namespace std;

class Solution {
 public:
	int lengthOfLongestSubstring(string s) {
		int count = 0;
		unordered_map<char, int> table;
		for (int i = 0, j = 0; i < s.size(); i++) {
			if (table.find(s[i]) != table.end()) {
				j = max(table[s[i]] + 1, j);
			}
			table[s[i]] = i;
			count = max(count, i - j + 1);
		}
		return count;
	}
};

int main() {
	Solution solution;
	cout << solution.lengthOfLongestSubstring("dvdf") << endl;
	cout << solution.lengthOfLongestSubstring("abcabcbb") << endl;
	return 0;
}