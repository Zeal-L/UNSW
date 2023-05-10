# 407: Construction Confusion

In `src/answers.txt`, write the alternative which most accurately answers the questions below. Each question's answer **must** be on a newline and be one of `a`, `b`, `c`, or `d` (note the lowercase).

1. Consider the below code snippet:
```cpp
std::vector<int> a(1, 2);
```
What is this line doing?
- a) Default construction.
- b) Construction via Direct Initialisation.
- c) Function declaration.
- d) From C++11 onwards, this is invalid syntax; won't compile.

2. Consider the below code snippet:
```cpp
std::vector<int> a{1, 2};
```
What is this line doing?
- a) From C++11 onwards, this is invalid syntax; won't compile.
- b) Function declaration.
- c) Construction via Aggregate Initialisation.
- d) Construction via Uniform Initialisation.

3. Consider the below code snippet:
```cpp
std::vector<int> b = {1, 2};
```
What is this line doing?
- a) Construction via Copy Initialisation.
- b) Construction by Assignment Initialisation.
- c) Construction via Uniform Initialisation.
- d) Construction via Direct Initialisation.

4. Consider the below code snippet:
```cpp
std::vector<int> a{1, 2};
std::vector<int> c = a;
```
What is this line doing?
- a) Construction via Copy Initialisation
- b) Copy assignment of `a` to `c`.
- c) Construction via Assignment Initialisation
- d) `c` is "stealing" the data members of `a` to construct itself.

5. Consider the below code:
```cpp
std::vector<int> a{1, 2};
std::vector<int> c;
c = a;
```
What is this line doing?
- a) Reconstruction of `c` from `a`.
- b) Construction via Copy Initialisation.
- c) Copy assignment of `a` to `c`.
- d) Aggregate assignment of `a` to `c`.

## Submission

This lab is due on Sunday 12th March @ 8pm.

Late submissions without [Special Consideration](https://www.student.unsw.edu.au/special-consideration) receive 0.

Submit by pushing your completed work to your main branch on Gitlab.