# 305: Inverse Mappings

`std::map` is one of the Standard Library's most widely used types (owing mainly to the fact that the need for an associative array appears in many places).

One not-so-common but still vitally important operation on a map is to invert its keys and values.
For example,
```cpp
auto m = std::map<std::string, int>{{"hi", 42}, {"bob", 6771}};
```
the inversion of `m` would be
```cpp
auto n = std::map<int, std::string>{{42, "hi"}, {6771, "bob"}};
```

As you can see, the keys have been swapped with their values and vice-versa.

Your task is to implement the `invert()` operation for a map of `std::string` to `int`, namely `std::map<std::string, int>`.

However, rather than a simple inversion, there is an added constraint.

If, after inversion, the same key appears more than once (which can happen due to values having different keys in the original map), only the key/value pair with the longest string should ultimately be in the resulting map.
For example, for the map `m`,
```cpp
auto m = std::map<std::string, int> {
    {"a", 6771},
    {"ab", 6771},
    {"abc", 6771},
    {"xyz", 6772},
};
```
it's inversion should be:
```cpp
auto n = std::map<int, std::string> {
    {6771, "abc"},
    {6772, "xyz"},
};
```

In `src/invert.cpp`, implement the `invert` operation and in `src/invert.test.cpp`, write at least **three** tests to ensure your code is correct!

## Submission

This lab is due on Sunday 5th March @ 8pm.

Late submissions without [Special Consideration](https://www.student.unsw.edu.au/special-consideration) receive 0.

Submit by pushing your completed work to your main branch on Gitlab.