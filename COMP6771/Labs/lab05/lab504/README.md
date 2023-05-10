# Stringing Spaceships

One thing C++ inherited from C was number literals in different bases.

For example, a base-16 literal looks like: `0xdeadbeef`.

A base-2 literal looks like: `0b1101001110011`.

In a compiler, these literals would be represented by some kind of specialised string class. This string class would naturally provide a way to determine if two number strings were in fact the same value.

Historically, this would have been done explicitly with `operator==` and with some implicit programmer knowledge that the strings were only _equivalent_ (values were the same) and not _equal_ (literally the same value, byte-by-byte).

As of C++20, the new spaceship operator finally lets us express in code what the true relationship is.

In `src/base_strings.h`, there are two `structs` that represent a base-16 number and a base-2 number as strings. You can assume that bytestrings follow the above formats and base-16 literals only use lowercase letters.

Your task is to write `operator<=>` overloads for both of these types.
Specifically:
- These two types when compared to each other should have a **weak ordering**. This means that they either compare less than, greater than, or equivalent, but not equal.
- It should still be possible to compare a base-2 number to a base-2 number and likewise for base-16 numbers. In these cases, the operator overload should be no more than a single line and also should return a `std::strong_ordering` instead.
- You do not need to write the operator overloads as friends.

Example:
```cpp
auto bstr = base2str{{"0b1101001110011"}};
auto hstr = base16str{{"0xdeadbeef"}};

CHECK(bstr <=> hstr == std::weak_ordering::less);
CHECK(hstr <=> bstr == std::weak_ordering::greater);
CHECK(bstr <=> bstr == std::strong_ordering::equal);
CHECK(hstr <=> hstr == std::strong_ordering::equal);
```

You will also need to write at least **two** tests in `src/base_strings.test.cpp` to ensure your code is correct.

## Submission

This lab is due on Sunday 19th March @ 8pm.

Late submissions without [Special Consideration](https://www.student.unsw.edu.au/special-consideration) receive 0.

Submit by pushing your completed work to your main branch on Gitlab.
