# 803: Calculated Expression

A common pattern in compilers is to represent the various elements of a programming language as classes and to naturally model the Abstract Synax Tree* as a class hierarchy.

Inspired by compiler writers of old, a budding C++ expert wrote a small program in `src/expression.cpp` which, using such a class hierarchy that represents fundamental arithmetic (`+`, `-`, `*`, and `/`), calculates a very special number and outputs it (with some supplementary text) to the terminal.

Unfortunately, this programmer was not elite enough to finished the class hierarchy implementation. He was, however, able to stub out the Abstract Base Class which the required base classes should derive from.

Your task is to complete what this young and enthusiastic programmer set out to do such that `expression.cpp` successfully compiles, runs, and produces the following output:
```text
COMP6771: Advanced C++ Programming
```
**Note**: each line is terminated with a newline.

You should implement the rest of the solution in `src/expr.h` and/or `src/expr.cpp`.

*: not required knowledge.

## Submission

This lab is due on Sunday 9th April @ 8pm.

Late submissions without [Special Consideration](https://www.student.unsw.edu.au/special-consideration) receive 0.

Submit by pushing your completed work to your main branch on Gitlab.
