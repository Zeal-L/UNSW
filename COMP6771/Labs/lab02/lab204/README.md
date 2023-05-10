# 204: Programmable Errors

In `src/answers.txt`, write the alternative which most accurately answers the questions below. Each question's answer **must** be on a newline and be one of `a`, `b`, `c`, or `d` (note the lowercase).

1. What kind of error is first displayed in the below code?
```cpp
// api.h
int rand();

// me.cpp
#include "api.h"
int rand() {
    return 42;
}

// you.cpp
int rand() {
    return 6771;
}

// client.cpp
#include "api.h"
int i = rand();
```
- a) Compile-time error: `you.cpp` did not include `api.h`
- b) Compile-time error: multiple definitions of `rand()`.
- c) Link-time error: multiple definitions of `rand()`.
- d) Logic Error: 6771 is not a random number!

2. What kind of error is first displayed in the below code?
```cpp
namespace constants {
  #define N 6771  
}

int N = constants::N;

int main() {
    int ints[N] = {1, 2, 3};
}
```
- a) Logic error: `constants` is a bad name for a namespace
- b) Compile-time error: macros do not obey namespace rules and so `int N` is changed to `int 6771`.
- c) run-time error: main does not return a value.
- d) Compile-time error: `N` is not const and so cannot be used in `ints[N]`.

3. What kind of error is displayed in the below code?
```cpp
#include <vector>

int main() {
    std::vector<int> v;
    unsigned i;
    while (i-- > 0) {
        v.push_back(i);
    }
}
```
- a) Link-time error: `i` is just a variable declaration and the real `i` hasn't been defined yet.
- b) Logic error: `i` is uninitialised and so its use is illegal.
- c) Logic error: `v` is not used after the for-loop.
- d) Run-time error: pushing back continuously to a vector can result in an "out of memory" error

4. What kind of error is displayed in the below code?
```cpp
int main() {
    int *ptr = new int{42};

    *ptr = 6771;

    return *ptr;
}
```
- a) Logic-error: you are only allowed to return numbers in the range [-128, 128] from `main()`.
- b) Runtime-error: `new` can fail allocation and throws an exception if that happens
- c) Compile-time error: `int{42}` is invalid syntax.
- d) Logic-error: programmer did not check if `ptr` was `nullptr` or not before dereferencing.

## Submission

This lab is due on Sunday 26th February @ 8pm.

Late submissions without [Special Consideration](https://www.student.unsw.edu.au/special-consideration) receive 0.

Submit by pushing your completed work to your main branch on Gitlab.