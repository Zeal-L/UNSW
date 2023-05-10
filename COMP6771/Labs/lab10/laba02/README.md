# a02: Bound Up

In `src/answers.txt`, write the alternative which most accurately answers the questions below. Each question's answer **must** be on a newline and be one of `a`, `b`, `c`, or `d` (note the lowercase).

Consider the following code:
```cpp
void value(std::string v) {}
void lvalue(std::string &lv) {}
void c_lvalue(const std::string &clv) {}
void rvalue(std::string &&rv) {}
void tvalue(auto &&tv) {}

int main() {
  value("hello");
  lvalue("hello"); // Won't compile
  c_lvalue("hello");
  rvalue("hello");
  tvalue("hello");

  std::string s0 = "world";
  std::string s1 = "world";
  std::string s2 = "world";
  std::string s3 = "world";
  std::string s4 = "world";
  std::string s5 = "world";
  value(s0);
  lvalue(s0);
  c_lvalue(s0);
  rvalue(s0); // Won't compile
  tvalue(s0);

  value(std::move(s1));
  lvalue(std::move(s2)); // Won't compile
  c_lvalue(std::move(s3));
  rvalue(std::move(s4));
  tvalue(std::move(s5));
}
```

1. Why won't `lvalue("hello")` compile?
- a) `"hello"` is actually a `const char *` and not a `std::string &`.
- b) `"hello"` would bind to `lvalue()` if we appended the literal suffix `s` to it.
- c) `"hello"` is implicitly converted to a `std::string`, but temporaries cannot bind to mutable lvalue references.
- d) `lv` (function parameter) is not used and under all compiler environments this is a compilation error.

2. Why won't `rvalue(s0)` compile?
- a) `s0` is a `std::string` and, when used in a function call expression, will be converted to an lvalue reference. Lvalue references cannot bind to rvalue references.
- b) `s0` is a `std::string` and values cannot bind to rvalue references.
- c) We have to use to `std::move()` to convert `s0` to an rvalue reference otherwise this program has undefined behaviour.
- d) `rvalue` is not const-qualified.

3. Why does `c_lvalue(std::move(s3))` compile?
- a) Because we have used a special compiler flag to make this compile (`-pedantic`)
- b) The rvalue from `std::move(s3)` is about to go out of scope, and it is illegal to modify rvalues. Luckily, `c_lvalue`'s parameter is const, so this isn't an issue.
- c) The compiler knows `s4` is never used again after this function call, so it is type-safe to bind an rvalue reference to a const lvalue reference.
- d) Everything, even rvalue references, are convertible to const lvalue references.

4. What is the deduced type of `tv` in each of `tvalue()`'s calls?
- a)
  1. tv: `const char *`
  2. tv: `const std::string &`
  3. tv: `std::string`
- b)
  1. tv: `const char *`
  2. tv: `std::string &`
  3. tv: `std::string &&`
- c)
  1. tv: `const char(&)[6]`
  2. tv: `const std::string &`
  3. tv: `std::string`
- d)
  1. tv: `const char(&)[6]`
  2. tv: `std::string &`
  3. tv: `std::string &&`


## Submission

This lab is due on Sunday 23rd April @ 8pm.

Late submissions without [Special Consideration](https://www.student.unsw.edu.au/special-consideration) receive 0.

Submit by pushing your completed work to your main branch on Gitlab.
