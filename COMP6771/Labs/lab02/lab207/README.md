# 207: Sorting Sequences

The C++ Standard Library provides many [algorithms](https://en.cppreference.com/w/cpp/header/algorithm), one very widely-used one being [std::sort](https://en.cppreference.com/w/cpp/algorithm/sort). `std::sort` accepts two iterators denoting a range and performs an optimised sort on that range.

In this exercise, we shall explore what requirements `std::sort` expects this pair of iterators to satisfy and how the [sequence containers](https://en.cppreference.com/w/cpp/container) `std::vector`, `std::list`, and `std::array` satisfy these requirements.

In `src/assortment.cpp` there are 3 overloads for a function `sort()` which accepts a vector, array, and list of integers. There are also three test cases in `src/assortment.test.cpp` for sanity checking.
Try implementing each `sort()` function using `std::sort`.

You may notice that the program will not compile.
Consider these questions:
- Where in the code is the compilation error happening?
- **Why** is this compilation error happening? (hint: the compiler error may only be a symptom, not the cause!)
- How might one resolve this error? (Hint: `std::vector` is always handy...)

Modify your implementation such that now the tests pass.

## Submission

This lab is due on Sunday 26th February @ 8pm.

Late submissions without [Special Consideration](https://www.student.unsw.edu.au/special-consideration) receive 0.

Submit by pushing your completed work to your main branch on Gitlab.