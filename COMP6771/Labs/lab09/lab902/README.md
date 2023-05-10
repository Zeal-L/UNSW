# 902: Instantiation

In `src/answers.txt`, write the alternative which most accurately answers the questions below. Each question's answer **must** be on a newline and be one of `a`, `b`, `c`, or `d` (note the lowercase).

1. Consider the following code:
```cpp
#include <string>

template <typename T>
T my_max(T a, T b) {
	return b < a ? b : a;
}

auto main() -> int {
	auto result = 7;
    auto cat = std::string{"cat"};
    auto dog = std::string{"dog"};
    
	my_max(1, 2);
	my_max(1.0, 2.0);
	my_max(cat, dog);
	my_max('a', 'z');
	my_max(7, result);
	my_max(cat.data(), dog.data());
}
```
How many template instantiations are there (not including any from `std::string`)?
- a) 6
- b) 5
- c) 3
- d) 4

2. Consider the following code:
```cpp
template <typename T, int N>
class array {
public:
    array() : elems_{} {}

    const T *data() const;

private:
    T elems_[N];
};

template<typename T, int I>
void manipulate_array(const array<T, I> arr) {
    arr.data(); // such a complex manipulation;
}

int main() {
    void (*fp1)(const array<int, 3>) = manipulate_array;
    void (*fp2)(const array<float, 3>) = manipulate_array;
    void (*fp3)(const array<char, 4>) = manipulate_array;

    array<float, 3> arr;
    (*fp2)(arr);
}
```
How many (function, class, member) template instantiations are there?
- a) 3
- b) 4
- c) 5
- d) 6

## Submission

This lab is due on Sunday 16th April @ 8pm.

Late submissions without [Special Consideration](https://www.student.unsw.edu.au/special-consideration) receive 0.

Submit by pushing your completed work to your main branch on Gitlab.
