# 503 Value-centric C++ (2/2)

C++ has value semantics by default (rather than reference semantics like other languages, such as Java). Classes allow developers to write their own value-types that act, look, and feel like the regular built-in types like `int` or `double`.

In this exercise we will be extending the previous `rational_number` class to feel more like a built-in type by replacing some of its operations with operator overloads.

In `src/rational_oo.h` and/or `src/rational_oo.cpp`, modify the `rational_number` class by:
- Replacing the previous `add(), sub(), mul(), div()` friend functions with their respective overloaded operators. You should consider the signatures of the above functions when deciding which overloaded operator to replace them with.
- Replacing the previous `eq(), ne()` friend functions with their respective overloaded operators. You should consider the signatures of the above functions when deciding which overloaded operator to replace them with.
- Replacing the previous `value()` member function with a type conversion operator to get the value of the rational number as a `double`.
- Adding a new operator overload for `operator[]` that:
    - When passed `'^'`, returns the numerator.
    - When passed `'v'`, returns the denominator.
    - There should be both a getter and setter version of this operator.
    - You can assume this function will only ever be passed one of `'^'` or `'v'`

Modify your previous tests so that they now use the overloaded operators. This means you should have at least **three** tests.

## Submission

This lab is due on Sunday 19th March @ 8pm.

Late submissions without [Special Consideration](https://www.student.unsw.edu.au/special-consideration) receive 0.

Submit by pushing your completed work to your main branch on Gitlab.
