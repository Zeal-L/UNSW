# 304: Reversal

In `src/answers.txt`, write the alternative which most accurately answers the questions below. Each question's answer **must** be on a newline and be one of `a`, `b`, `c`, or `d` (note the lowercase).

Consider the following code:
```cpp
#include <iostream>
#include <vector>

int main() {
	std::vector<int> temperatures = {32, 34, 33, 28, 35, 28, 34};

	for (int i = 0; i < temperatures.size(); ++i) { // (*)
		std::cout << temperatures.at(i) << " ";
	}
	std::cout << "\n";

	for (const auto &temp : temperatures) {         // (^)
		std::cout << temp << " ";
	}
	std::cout << "\n";

	for (auto iter = temperatures.cbegin(); iter != temperatures.cend(); ++iter) { // (&)
		std::cout << *iter << " ";
	}
	std::cout << "\n";
}
```

1. Why is the for-loop marked with an (*) potentially more unsafe than the others?
- a) It is a C-style for-loop, and the index could overflow.
- b) It is a C-style for-loop, and the comparison of signed vs. unsigned integers can produce surprising results.
- c) It is a C-style for-loop, and this makes it inherently inferior to C++ style for-loops.
- d) It is a C-style for-loop, and it is possible we go off the end of the `temperatures` vector.

2. We want to iterate through `temperatures` in reverse. Which loop in this code is easiest to change and why?
- a) (*): Index calculations are easy to do and most people are used to seeing index-based reverse iteration
- b) (^): range for-loops and an appropriate use of std::reverse conveys our intent the best.
- c) (^): all standard library containers provide reverse iterators.
- d) (&): just change the `cbegin` and `cend` to `rbegin` and `rend`.

3. What differences, if any, are there between `temperatures.begin()` and `temperatures.rend()`?
- a) An end-iterator, whether from `end()` or `rend()` is "one-past-the-end", and so is never dereferenceable, unlike `begin()`.
- b) No difference: `begin()` == `rend()` since the beginning of a range is the end of its reversal.
- c) The only difference is the type: `begin()` returns an `iterator` whereas `rend()` returns `reverse_iterator`. Everything else is the same.
- d) `rend()` would only compare equal to `begin()` if `temperatures` was empty.

## Submission

This lab is due on Sunday 5th March @ 8pm.

Late submissions without [Special Consideration](https://www.student.unsw.edu.au/special-consideration) receive 0.

Submit by pushing your completed work to your main branch on Gitlab.