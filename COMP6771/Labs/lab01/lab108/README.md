# 108: Constant Referencing

In `src/answers.txt`, write the alternative which most accurately answers the questions below. Each question's answer **must** be on a newline and be one of `a`, `b`, `c`, or `d` (note the lowercase).

1. Are there any errors in this code and if so what are they?
```cpp
auto i = 3;
i = 4;
```
- a) Yes: `auto` is a reserved keyword
- b) Yes: it is illegal to initialise a variable after it is defined.
- c) Maybe: it depends on what CPU this code is run on.
- d) No: assignment after initialisation is legal, even in C.

2. Are there any errors in this code and if so what are they?
```cpp
const auto j = 5;
--j;
```
- a) Yes: `j` is a constant integer which cannot be modified.
- b) Maybe: it depends if the programmer prefers east or west const.
- c) No: decrementing a constant integer creates a new one.
- d) Yes: `auto` and `const` should not be mixed.

3. Are there any errors in this code and if so what are they?
```cpp
auto age = 18;
auto& my_age = age;
++my_age;
```
- a) Maybe: it depends if the code is compiled as C++98 or C++11 or higher.
- b) No: my_age is a reference to age, so preincrement is perfectly legal.
- c) Yes: references are inherently const and so modifying `age` through `my_age` is illegal.
- d) No: `my_age` is a copy of `age` and modifying `my_age` has no impact on `age` whatsoever.

4. Are there any errors in this code and if so what are they?
```cpp
auto age = 21;
const auto &my_age = age;
--my_age;
```
- a) Yes: `auto` references can only be used with explicit type annotations.
- b) Maybe: if this code is compiled with the "-pedantic" flag in GCC, it would be perfectly legal.
- c) No: my_age is a const reference, but `age` is not constant, so this is fine.
- d) Yes: `my_age` is a reference to a constant integer, which cannot be modified.
