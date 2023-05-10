# 505: Questionable Overloads

In `src/answers.txt`, write the alternative which most accurately answers the questions below. Each question's answer **must** be on a newline and be one of `a`, `b`, `c`, or `d` (note the lowercase).

1. Consider the following class:
```cpp
class vec3 {
public:
  vec& operator+=(const vec &p);
  vec& operator-=(const vec &p);

  vec& operator*=(const vec &p);

private:
  int x_;
  int y_;
  int z_;
};
```
Why would this be considered not a very wise decision to provide an overload for `operator*=`?
- a) The semantic of multiplying two vectors together does not exist.
- b) `operator*=` should be replaced with `operator/=`, which makes more mathematical sense.
- c) `operator*=` obscures the actual logic of the operation and can potentially obfuscate code.
- d) The semantic of multiplying two vectors together is ambiguous. Dot or Cross product?

2. Consider the following class:
```cpp
class i32 {
public:
  friend i32 operator&&(const i32 &, const i32 &);
  friend i32 operator||(const i32 &, const i32 &);

private:
  std::int32_t i_;
}
```
Could this be considered to be a valid use of operator overloading? Why or why not?
- a) Valid: we are boxing a native 32-bit integer to work like a built-in `int`, where && and || are well-defined.
- b) Invalid: logical-AND and logical-OR are defined on booleans, not integers (of any size).
- c) Valid: for two `int`s `i1` and `i2`, `i1` && `i2` produces a reasonable result.
- d) Invalid: as written, these overloads only work with `i32`, but it is possible to AND and OR together other types with `i32` too, such as booleans. The overloads should accept a more general type.

## Submission

This lab is due on Sunday 19th March @ 8pm.

Late submissions without [Special Consideration](https://www.student.unsw.edu.au/special-consideration) receive 0.

Submit by pushing your completed work to your main branch on Gitlab.
