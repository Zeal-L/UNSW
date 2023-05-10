# 502: Overloaded Operators

In `src/answers.txt`, write the alternative which most accurately answers the questions below. Each question's answer **must** be on a newline and be one of `a`, `b`, `c`, or `d` (note the lowercase).

For the following questions, consider the below class:
```cpp
class vec3 {
public:
    auto operator[](int n) { return elems_[n]; }

    friend auto operator>>(std::istream &is, vec3 &v) -> std::istream&;

private:
    double elems_[3] = {0, 0, 0};
}
```

1. In what cases would one need to overload an operator for a const and non-const version?
- a) Always; it is impossible to know how your code will be used in the future.
- b) Only when the operator is a member function and not a non-member function.
- c) When the operator has both a "getter" and "setter" version the two overloads are necessary.
- d) You should only add a const version if the return type is a reference type.

2. What could be the return type of `vec3::operator[]` as it is currently written?
- a) `double *`
- b) `double &`
- c) `volatile double`
- d) `double[]`

3. Is the `vec3` class currently const-correct? If not, how would you change it to be so?
- a) Not const-correct: `operator[]()` needs a const version so const-objects can still be indexed into. The returned value must not be modifiable, however.
- b) const-correct: `elems_` is not const, so this class can never have const-qualified methods.
- c) Not const-correct: the `int n` parameter in `operator[]()` is not bottom-level const-qualified.
- d) const-correct: `auto` correctly deduces the right const-correct type depending on if `this` is a const-object or not.

4. Given the serialised format for a `vec3` is `double1 double2 double3`, what could be a _potential_ implementation for `operator>>` and why?
```cpp
// a
// fill the 3 elems of v via a standard algorithm.
// no need to return "is" for chaining (due to the serialised format of vec3)
auto operator>>(std::istream &is, vec3 &v) -> std::istream& {
    std::copy(std::istream_iterator<double>{is}, std::istream_iterator<double>{}, v.elems_, v.elems_ + 3);
}

// b
// fill the 3 elems of v.
// return "is" for chaining.
auto operator>>(std::istream &is, vec3 v) -> std::istream& {
    is >> v.elems_[0];
    is >> v.elems_[1];
    is >> v.elems_[2];
    return is;
}

// c
// fill the 3 elements of v from is.
// return "is" for chaining.
auto operator>>(std::istream &is, vec3 &v) -> std::istream& {
    is >> v.elems_[1];
    is >> v.elems_[2];
    is >> v.elems_[3];
    return is;
}

// d
// fill the 3 elems of v via a standard algorithm.
// return "is" for chaining.
auto operator>>(std::istream &is, vec3 &v) -> std::istream& {
    std::copy(std::istream_iterator<double>{is}, std::istream_iterator<double>{}, v.elems_);
    return is;
}
```

5. Is friendship necessary for `vec3`'s `operator>>` overload? Why or why not?
- a) Necessary: every implementation must use `elems_`, which is private -- can only access this via friendship.
- b) Necessary: non-member operator overloads should always be hidden friends.
- c) Not necessary: `operator>>` could potentially use `vec3::operator[]()` (which is public) to fill the vec3's elements, so defining it as a friend is superfluous.
- d) Not necessary: `operator>>` can be implemented as a member function, and we only ever use it like so: `my_vec3 >> std::cin`

## Submission

This lab is due on Sunday 19th March @ 8pm.

Late submissions without [Special Consideration](https://www.student.unsw.edu.au/special-consideration) receive 0.

Submit by pushing your completed work to your main branch on Gitlab.
