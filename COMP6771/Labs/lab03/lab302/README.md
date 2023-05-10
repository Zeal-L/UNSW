# 302: Vowel Sort

A powerful aspect of `std::sort` is being able to change the meaning of "sorted" by supplying a different comparator to the sort.

In olden times, this would be done by crafting a separate function each time and supplying a function pointer.
As of C++11, this is now all doable inline with `lambda` functions.

How might we use a lambda function to sort a vector of strings by the number of vowels in each string?
Furthermore, if the number of vowels are equal, then the strings should be lexicographically sorted.

In `src/vsort.cpp`, there is a stub for a function that accepts a vector of strings and sorts it according to the above rules.

You need to implement this function using a lambda as the custom comparator.
You should also write at least **two** tests to verify that your code is correct.

## Submission

This lab is due on Sunday 5th March @ 8pm.

Late submissions without [Special Consideration](https://www.student.unsw.edu.au/special-consideration) receive 0.

Submit by pushing your completed work to your main branch on Gitlab.