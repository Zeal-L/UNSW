# 904: Special Selection

In `src/answers.txt`, write the alternative which most accurately answers the questions below. Each question's answer **must** be on a newline and be one of `a`, `b`, `c`, or `d` (note the lowercase).

1. Consider the following code:
```cpp
template <typename ...Ts>
struct sink {}; /* 1 */

template <typename T>
struct sink<int, T> {}; /* 2 */

template <typename T, typename ...Ts>
struct sink<int, Ts...> {}; /* 3 */

using sunk = sink<int, void>;
```
Which specialisation would be selected and why?
- a) (3): This is the only specialisation where the first template parameter matches perfectly, and `Ts...` has higher priority than a single `T`.
- b) (2): This is the only specialisation where the first template parameter matches perfectly, and `Ts...` has lower priority than a single `T`.
- c) (1): The primary template is the most general of all of the specialisations and so it is the best match.
- d) Compilation error: 2 & 3 are equally viable.

**Answer**: (b)

2. Consider the following code:
```cpp
template <typename T, const int *Arr>
struct sink {}; /* 1 */

template <typename T, auto Arr>
struct sink<const T, Arr> {  }; /* 2 */

template <typename T, const int *Arr>
struct sink<T&, Arr> {}; /* 3 */

constexpr int arr[3] = {};
using sunk = sink<const short&, arr>;
```
Which specialisation would be selected and why?
- a) (3): `arr` decays to a `const int *` and matches (3)'s template parameter pefectly and `T&` has higher priority over `const T` and `T`.
- b) (2): `auto` non-type template parameters are more flexible than other types and are preferred. Also, `const T` has higher preference over `T&` and `T`.
- c) (1): 2 & 3 are ambiguous since `const T` is equally viable with `T&` in this case. The compiler falls back on (1).
- d) (3): (3)'s `const int *` non-type template parameter aligns with the primary template's non-type template parameter pefectly, so it is by default the most specialised candidate.

3. Consider the following code:
```cpp
template <typename T>
void foo(T);              /* 1 */ 

template <typename T>
void foo(T *);            /* 2 */

template <>
void foo(int *);          /* 3 */ 

void foo(const int *);    /* 4 */ 

int main() {
  int p = 0;
  foo(&p);
}
```
Which specialisation would be selected and why?
- a) (1): Being the most general, this function template can be used with any argument, and so is selected as it is the best match in all cases of calls to `foo()` with a single argument.
- b) (2): In overload resolution, (1), (2), and (4) are considered. (1) does not match a pointer as well as (2) and (4), so it drops out. The compiler is able to synthesise a function that matches `int *` better than `const int *`, so (4) drops out. The compiler then instantiates (2), as (3) is an explicit specialisation, which is not allowed according to the C++ Standard.
- c) (4): `int *` is always convertible to a `const int *` and is a real function (rather than a template). Therefore, it is the best match.
- d) (3): In overload resolution, (1), (2), and (4) are considered. (1) does not match a pointer as well as (2) and (4), so it drops out. The compiler is able to synthesise a function that matches `int *` better than `const int *`, so (4) drops out. Finally, the compiler searches for any relevant specialisations of (2) and finds (3), so it is selected.

## Submission

This lab is due on Sunday 16th April @ 8pm.

Late submissions without [Special Consideration](https://www.student.unsw.edu.au/special-consideration) receive 0.

Submit by pushing your completed work to your main branch on Gitlab.
