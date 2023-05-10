# 903: Tuples of Templates

Complete the below struct and function template specification in `src/tuple.h`.

There is a client program in `src/tuple.cpp` that uses `tuple`. You have successfully completed this lab when this program compiles and produces the following output:
```
1
3.14
a
$w@G
```
**Note**: each line is terminated by a newline.

**Note**: you are not allowed to modify `src/tuple.cpp`.

## `struct tuple`

A tuple is compile-time heterogenous list of types. The C++ Standard Library provides `std::tuple`, but it is an extremely complex class template, far too hard to understand for a mere mortal.

Instead, we will be writing a much simpler version of `tuple` that only uses basic composition and class template specialisation. As part of being much simpler, our version of `tuple` will always have at least one element inside of it.

### Template Parameters

|Name|Kind|Description|
|----|----|-----------|
|`T`|`typename`|The element type at this position of the tuple.|
|`Ts`| Variadic pack of 0 or more `typename`s|The remaining types of the tuple to be composed.|

### Mandatory Internal Representation

For a tuple with **only a single element**:
|Data Member|Description|
|-----------|-----------|
|`T elem`|The element at this position of the `tuple`.|

For a tuple with **more than a single element**:
|Data Member|Description|
|-----------|-----------|
|`T elem`|The element at this position of the `tuple`.|
|`tuple<Ts...> cons`|The remaining elements of the tuple as a recursive subobject.|

### (constructor)

None. The tuple uses [aggregate initialisation](https://en.cppreference.com/w/cpp/language/aggregate_initialization) for construction since it is a POD (plain-old datatype).

### Non-Member Utilities
```cpp
template <std::size_t, typename T, typename ...Ts>
auto get(const tuple<T, Ts...> tp);
```
Gets the `I`'th element from the tuple `tp`. Tuples are 0-indexed, just like arrays.
- If `tp` has less elements than `I`, the code should not compile.
- Otherwise, returns the element at position `I`.

**Note**: this function template intentionally has only an `auto` return type. It is not possible to write this function template with an explicitly specified return type due to conversion errors.

### Deduction Guide

It should be possible to deduce the types of a `tuple` from the below expression:
```cpp
auto tp = tuple{1, 2, 3};
```
You must a Class Template Deduction Guide to allow code like this to compile.

### Hints
* To successfully complete this lab, you will likely need to master class template specialisation.
* Function templates **cannot** be partially specialised and **should not** be explicitly specialised.
* It may be easy to write `get<>()` with a recursive solution in mind...

### Other Notes:
* We have turned off the warning about "missing braces around subobjects" (-Wno-missing-braces) to allow for the flat initialisation syntax of the tuple in `main()`. Whether or not this is acceptable in a real codebase is debatable.

## Submission

This lab is due on Sunday 16th April @ 8pm.

Late submissions without [Special Consideration](https://www.student.unsw.edu.au/special-consideration) receive 0.

Submit by pushing your completed work to your main branch on Gitlab.
