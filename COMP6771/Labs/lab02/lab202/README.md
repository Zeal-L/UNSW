# 202: Resolution Overload

In `src/answers.txt`, write the alternative which most accurately answers the questions below. Each question's answer **must** be on a newline and be one of `a`, `b`, `c`, or `d` (note the lowercase).

1. Consider the code below:
```cpp
/* 1 */ auto put(char) -> void;
/* 2 */ auto put(int) -> void;
/* 3 */ auto put(const char) -> void;
/* 4 */ auto put(char &) -> void;

put('a');
```
Which overload of `put` would be selected and why?
- a) Overload 1: `put` was called with a `char` and overload 3 is just a redeclaration of overload 1.
- b) Overload 2: `char` is implicitly promotable to `int` and so overload 2 is the best match.
- c) Overload 3: `put` was called with a temporary `const char`.
- d) Overload 4: `put` was called with a temporary `char` and temporaries preferentially bind to references.


2. Consider the code below:
```cpp
/* 1 */ auto put(char) -> void;
/* 2 */ auto put(char &) -> void;
/* 3 */ auto put(const char &) -> void;
char c = 'a';
put(c);
```
Which overload of `put` would be selected and why?
- a) Overload 1: `put` was called with a `char`.
- b) Overload 2: `put` was called with a mutable `char` and and references have higher priority.
- c) Overload 3: `put` was called with a const `char` and const references have higher priority.
- d) No overload: this call is ambiguous.


3. Consider the code below:
```cpp
/* 1 */ auto memcpy(char *dst, const char *src, int n = 0) -> void *;
/* 2 */ auto memcpy(const char *dst, char * const src) -> char *;

char *dst = /* appropriate initialisation... */;
const char *src = /* appropriate initialisation... */;

void *ptr = memcpy(dst, src);
```
Which overload of `memcpy` would be selected and why?
- a) Overload 1: both overloads are equally viable but the return type of overload 1 matches `ptr`'s type better
- b) Overload 2: has exactly two arguments and a non-bottom-level const pointer is always convertible to a bottom-level const pointer.
- c) Overload 1: the first two arguments match perfectly and the default argument is used for the third.
- d) Overload 2: the top-level const `src` argument has higher priority than the corresponding bottom-level const `src` in overload 1.


4. Consider the code below
```cpp
/* 1 */ auto min(int(&arr)[2]) -> int;
/* 2 */ auto min(int *arr) -> int;
/* 3 */ auto mint(int(&arr)[]) -> int;

auto fn(int buf[3]) -> void {
    min(buf);
}
```
Which overload of `min` would be selected and why?
- a) Overload 1: though `min` was called with an array of length 3, 3 is close to 2, so this is the best match.
- b) Overload 2: the `buf` argument decays to `int *` and so overload 2 is the best match.
- c) Overload 3: neither `int(&)[2]` nor `int *` match `int(&)[3]` perfectly but a reference to an array of unknown length does, so this is the best match.
- d) No Overload: this call is ambigous.


5. Consider the code below:
```cpp
/* 1 */ auto sink(int i, ...);
/* 2 */ auto sink(int i, short s);
/* 3 */ auto sink(...);

auto L = std::numeric_limits<long>::max();
sink(1, L);
```
Which overload of `sink` would be selected and why?
- a) Overload 1: correct number of parameters and a variadic function is preferred over a narrowing conversion from `long` to `short`
- b) Overload 2: correct number of parameters and variadic functions have the lowest priority in overload resolution, so this is the only viable candidate.
- c) Overload 3: by definition, a single-parameter variadic function can be called with any number and type of arguments, so it is always the best match.
- d) No Overload: this call is ambigous.

## Submission

This lab is due on Sunday 26th February @ 8pm.

Late submissions without [Special Consideration](https://www.student.unsw.edu.au/special-consideration) receive 0.

Submit by pushing your completed work to your main branch on Gitlab.