# 308: Microbenchmarking Lookup

The various containers in the C++ Standard Library have different performance characteristics for different operations. For example, linear search in `std::vector` is presumed to be faster than in `std::list`, but potentially slower than in a `std::deque`.

In this activity, we will put these assumptions to the test with a microbenchmark!

In `src/microbenchmark.h`, there is documentation for a function that is to run a microbenchmark for a list, deque, and vector simultenously. This function should return a `timings` structure, which is also in the provided header file.

Complete this function in `src/microbenchmark.cpp`. We have provided a random-number generator in there for you to use.

When you are done, you should also write at least **one** test in `src/microbenchmark.test.cpp`. You may wish to use the test as a way to verify/test your assumption about which container is the fastest for linear lookup...

Though not mandatory, you may also want to write a small program that uses your benchmarking code and does experiments to see under what conditions which container is faster. If you do so, it may help to consider these questions:
- What design and implementation trade-offs have been made between the various sequential containers?
- Has the programming-paradigm (i.e. OOP) of these datastructures made a difference?
- Has modern hardware been fully taken advantage of?

Feel free to discuss your answers to these questions with your tutor.

Hint: a useful library that deals with all things related to time (and dates!) is [`std::chrono`](https://en.cppreference.com/w/cpp/chrono).

## Submission

This lab is due on Sunday 5th March @ 8pm.

Late submissions without [Special Consideration](https://www.student.unsw.edu.au/special-consideration) receive 0.

Submit by pushing your completed work to your main branch on Gitlab.