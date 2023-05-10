# 306: Categorising Iterators

In `src/answers.txt`, write the alternative which most accurately answers the questions below. Each question's answer **must** be on a newline and be one of `a`, `b`, `c`, or `d` (note the lowercase).


1. Consider this code:
```cpp
#include <vector>
int main() {
    const std::vector<int> v;
    auto iter = v.begin();
}
```
What iterator type and category is `iter`?
- a) constant iterator / random-acess
- b) `const_iterator` / contiguous
- c) constant `const_iterator` / contiguous
- d) won't compile



2. Consider this code:
```cpp
#include <vector>
int main() {
    const std::vector<int> v;
    auto iter = v.cbegin();
}
```
What iterator type and category is `iter`?
- a) `const_iterator` / contiguous
- b) constant `const_iterator` / contiguous
- c) constant iterator / contiguous
- d) won't compile



3. Consider this code:
```cpp
#include <vector>
int main() {
    const std::vector<int> v;
    auto iter = (*vec.begin())++;
}
```
What iterator type and category is `iter`?
- a) `const_iterator` / contiguous
- b) constant iterator / contiguous
- c) constant `const_iterator` / contiguous
- d) won't compile



4. Consider this code:
```cpp
#include <list>
int main() {
    std::list<int> li;
    auto iter = li.cbegin();
}
```
What iterator type and category is `iter`?
- a) constant iterator / bi-directional
- b) iterator / forward
- c) `const_iterator` / bi-directional
- d) won't compile



5. Consider this code:
```cpp
#include <forward_list>
int main() {
    std::forward_list<int> forward_li;
    auto iter = forward_li.cbegin();
}
```
What iterator type and category is `iter`?
- a) `const_iterator` / forward
- b) constant iterator / forward
- c) iterator / bidirectional
- d) won't compile



6. Consider this code:
```cpp
#include <forward_list>
int main() {
    const std::forward_list<int> forward_li;
    auto iter = (*forward_li.begin())++;
}
```
What iterator type and category is `iter`?
- a) `const_iterator` / forward
- b) iterator / forward
- c) `iter` is an `int`
- d) won't compile



7. Consider this code:
```cpp
#include <set>
int main() {
    std::set<int> st;
    const auto iter = st.begin();
}
```
What iterator type and category is `iter`?
- a) constant iterator / bidirectional
- b) iterator / forward
- c) iterator / bi-directional
- d) won't compile



8. Consider this code:
```cpp
#include <string>
int main() {
    std::string s;
    auto iter = s.begin();
}
```
What iterator type and category is `iter`?
- a) iterator / forward
- b) iterator / contiguous
- c) iterator / random-access
- d) won't compile



9. Consider this code:
```cpp
#include <iterator>
#include <iostream>
int main() {
    auto iter = std::istream_iterator<int>(std::cin);
}
```
What iterator type and category is `iter`?
- a) `const_iterator` / input
- b) iterator / input
- c) iterator / forward
- d) won't compile



10. Consider this code:
```cpp
#include <iterator>
#include <iostream>
int main() {
    auto iter = std::ostream_iterator<int>(std::cout, " ");
}
```
What iterator type and category is `iter`?
- a) iterator / output
- b) `const_iterator` / output
- c) constant iterator / input
- d) won't compile

## Submission

This lab is due on Sunday 5th March @ 8pm.

Late submissions without [Special Consideration](https://www.student.unsw.edu.au/special-consideration) receive 0.

Submit by pushing your completed work to your main branch on Gitlab.