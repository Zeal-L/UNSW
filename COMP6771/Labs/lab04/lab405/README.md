# 405: Value-centric C++ (1/2)

C++ has value semantics by default (rather than reference semantics like other languages, such as Java). Classes allow developers to write their own value-types that act, look, and feel like the regular built-in types like `int` or `double`.

In this exercise we begin to create our own value-type representing a rational number. Rational numbers are any number that can be represented as a fraction with integer numerator and denominator. Note that `x/0` for any `x` is not a rational number.

In `rational.cpp`, implement the `rational_number` class and write at least **three** tests for it.

The class should have:
- a static public data member `null`, which represents "no" rational number. This should be implemented as an empty `std::optional<rational_number>`.
- a public static member function `auto make_rational(int num, int denom) -> std::optional<rational_number>` that returns either a rational number or the above static data member if `denom == 0`.
- a private constructor, so that a user cannot accidentally create an invalid rational number (all creation must use `make_rational`).
- the four arithmetic operations `add(), sub(), mul(), div()` as friend functions so that, for `r1` and `r2` which have type `rational_number`, one may write: `add(r1, r2)`, etc.. The return type for `add(), sub(), mul()` should be `rational_number`, but for `div()` it should be `std::optional<rational_number>`.
- the two equality operations `eq` and `ne` so that, for `r1` and `r2` which have type `rational_number`, one may write `if (eq(r1, r2)) { ... }`. The return type for both of these functions should be `bool`.
    - **Hint**: equality for fractions doesn't necesarily mean the numerators and denominators are equal! E.g., 1/2 == 2/4...
- a public method `auto value() -> double` which returns the quotient of the numerator and the denominator as a `double`.

The size of every instance of your class should be no bigger than `16 bytes`.

## Submission

This lab is due on Sunday 12th March @ 8pm.

Late submissions without [Special Consideration](https://www.student.unsw.edu.au/special-consideration) receive 0.

Submit by pushing your completed work to your main branch on Gitlab.
