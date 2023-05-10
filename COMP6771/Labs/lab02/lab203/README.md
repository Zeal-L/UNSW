# 203: Type-Safe Scaling

C++ has a poignant emphasis on strong type-safety. To that end it offers a type-safe version of the C-style cast called `static_cast` which only allows conversion between compatible types e.g. `int` to `float`, `void *` to `int *` etc., and will not allow unrelated casts e.g. `void *` to `int`.

In this exercise we will use `static_cast` to safely scale a vector of integers by a `double` value and return a new vector of doubles.

In `scale.h` there is documentation for `scale()` which does this conversion.
Implement this function in `src/scale.cpp`.
You will also need to write at least **two** tests for it in `src/scale.test.cpp`.

To improve ease of use, also add a _default value_ of 0.5 for the scaling factor.
This will allow users to not have to pass a scale factor when commonly scaling a vector in half.

## Submission

This lab is due on Sunday 26th February @ 8pm.

Late submissions without [Special Consideration](https://www.student.unsw.edu.au/special-consideration) receive 0.

Submit by pushing your completed work to your main branch on Gitlab.