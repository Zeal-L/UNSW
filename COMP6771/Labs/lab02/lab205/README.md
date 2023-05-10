# 205: Finding a Mismatch

The **S**tandard **T**emplate **L**ibrary (aka the STL, now part of the C++ standard proper) has three fundamental concepts: containers, iterators, and algorithms. Iterators are the glue that sits between containers of data and the algorithms that operate on them. By using these three concepts together, code reuse is maximised and composition of existing code becomes very easy.

In this exercise you will be using `std::vector<int>::iterator` to implement a less general version of [std::mismatch](https://en.cppreference.com/w/cpp/algorithm/mismatch), one of the many algorithms provided by the standard library.

There is documentation for our version of `mismatch()` in mismatch.cpp. Complete this function and write at least **three** more tests to verify your code is correct. Two have already been provided for you.

## Submission

This lab is due on Sunday 26th February @ 8pm.

Late submissions without [Special Consideration](https://www.student.unsw.edu.au/special-consideration) receive 0.

Submit by pushing your completed work to your main branch on Gitlab.