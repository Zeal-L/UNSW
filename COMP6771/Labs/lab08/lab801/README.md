# 801: Order Of The Inheritance

Recall the order of construction and destruction in the face of base classes in C++:
* Construction:
    1. `virtual` base classes (assuming all parents also inherit that class virtually) in declaration order.
    2. Non-`virtual` bases in declaration order.
    3. Data members in declaration order.
    4. `this`'s constructor.

* Destructor:
    1. `this`'s destructor.
    2. Destructors of data members in reverse-declaration order.
    3. Non-`virtual` bases in reverse-declaration order.
    4. `virtual` base classes in reverse-declaration order.

In order to test their knowledge out, a budding C++ expert in `src/ordered.cpp` created a small program with this output:
```text
AAABCABAAABCADAAAB
~B~A~A~A~D~A~C~B~A~A~A~B~A~C~B~A~A~A
```
**Note**: each line is terminated by a newline.

This output consists of some configuration of inheritance and composition of four `struct`s that have been stubbed in `src/order.h` and `src/order.cpp`.

Your task is figure out the configuration of inheritance and composition of these four `struct`s such that `ordered.cpp` compiles and produces the above output. You have successfully completed this lab when your program does so.

**Important**: You are not allowed to modify `src/ordered.cpp`.

## Submission

This lab is due on Sunday 9th April @ 8pm.

Late submissions without [Special Consideration](https://www.student.unsw.edu.au/special-consideration) receive 0.

Submit by pushing your completed work to your main branch on Gitlab.
