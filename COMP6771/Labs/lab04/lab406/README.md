# 406: Defaults & Deletes

In `src/answers.txt`, write the alternative which most accurately answers the questions below. Each question's answer **must** be on a newline and be one of `a`, `b`, `c`, or `d` (note the lowercase).

1. Consider the below code:
```cpp
struct point2i {
    int x;
    int y;
};
```
Is this class-type default-constructible and why?
- a) No: We need to opt-in to a default aggregate initialiser.
- b) Yes: default aggreggate-initialisation would leave `x` and `y` uninitialised.
- c) No: This is a C-style struct; it has no default constructor.
- d) Yes: default aggregate-initialisation would set `x` and `y` to `0`.

2. Consider the below code:
```cpp
class employee {
public:
    employee(int employeeno);

private:
    int employeeno;
};
```
Is this class-type default-constructible and why?
- a) Yes: the compiler can automatically synthesise the default constructor if we don't provide one.
- b) No: a user-provided constructor prevents automatic synthesis of a default constructor.
- c) No: we have not provided an in-class member initialiser.
- d) Yes: `int` itself has a default constructor, so `employee`'s default constructor simply delegates to `int`'s one.

3. Consider the below code:
```cpp
struct point2i {
    point2i() = default;
    point2i(int x = 42, int y = 6771);

    int x;
    int y;
};
```
Is this class-type default-constructible and why?
- a) No: the two provided constructors are ambiguous when called with 0 arguments, so this code won't compile.
- b) Yes: we have explicitly defaulted the default constructor.
- c) Yes: Though both constructors can be called with 0 arguments, the compiler prefers the explicitly defaulted default-constructor.
- d) Yes: Though both constructors can be called with 0 arguments, in overload resolution the second constructor has higher priority, so it will be called.

4. Consider the below code:
```cpp
struct point2i {
    point2i() = default;
    point2i(const point2i &) = delete;
    point2i(point2i &&) = delete;
};

point2i get_point() { return point2i{}; }

point2i p = get_point();
```
Will this code compile and why?
- a) Yes: the default constructor will be called for `p`'s initialisation
- b) No: `point2i(point2i &&)` is invalid syntax.
- c) No: `point2i` is not copyable at all, so `p` cannot be initialised.
- d) Yes: `point2i` has no data members, so even though the copy and move constructors are deleted, the compiler knows that those constructors would have had no effect anyway.

5. Consider the below code:
```cpp
struct guard {
    guard() = default;
    guard(const guard &) = delete;
    guard(guard &&) = delete;
};

struct outer {
    guard g;
};
```
Is the `outer` class-type default-constructible or copyable and why?
- a) Neither default-constructible nor copyable: we have not explicitly told the compiler that we want `outer` to have the default constructor and copy/move constructors generated for us.
- b) Default-constructible but not copyable: `guard`'s explicitly deleted copy/move constructor prevents the implicitly generated copy/move constructors for `outer`. For a similar reason, `guard` does allow for the implicitly generated default constructor.
- c) Won't compile: `guard` prevents the implicit copy/move constructors for `outer` to be generated, as well the default constructor. Therefore, this class cannot be constructed, which is a compiler error.
- d) Default-constructible and copyable: `guard` has no effect on the implicitly generated default, copy, and move constructors for `outer` since it is a `struct`. If `outer` were a `class`, it would only be default-constructible, however.

## Submission

This lab is due on Sunday 12th March @ 8pm.

Late submissions without [Special Consideration](https://www.student.unsw.edu.au/special-consideration) receive 0.

Submit by pushing your completed work to your main branch on Gitlab.