# A01: Register Traits

Type traits are a C++ metaprogrammer's best friend. They allow *at compile-time* access to the properties of a types that other languages (such as Python, JS) can only emulate at runtime with an obvious performance cost.

It's time to join the worldwide consortium of metaprogrammers and go through the rite of passage and write your own very first type trait(s).

Complete the below trait specifications in `src/register.h` and write at least **four** tests for them in `src/register.test.cpp`.

## `size2reg`

This is a type trait that, given an integral size value, calculates what [CPU register](https://en.wikipedia.org/wiki/Processor_register) a type of this size would fit in to. If the size would not fit in a register, then the type trait gives `void`.

### Template Parameters

|Name|Kind|Description|
|----|----|-----------|
|`I`|Non-type Template Parameter|The size of a given type. The type of `I` itself is any integral type capable of holding the largest number (`std::size_t` is a good choice, but there are others).|

### Member Types

|Name|Description|
|----|-----------|
|`type`|The type of the register a type of this would fit into. The rules of the size are below.|

For a size `I`, the type is:
* `I == 1` => `std::uint8_t`
* `I == 2` => `std::uint16_t`
* `2 < I <= 4` => `std::uint32_t`
* `4 < I <= 8` => `std::uint64_t`
* Otherwise, `void`

### Convenience Alias

You also need to write an alias template `size2reg_t` that is equivalent to the pseudocode `size2reg<>::type`.

## `is_passable_in_register`

This is a type trait that, given a generic `T`, determines if this type would be passable in a register or not.

The rules for which are as follows:
1. If `T` is a fundamental type, it is always passable in a register.
2. If `T` is a **trivial type** that fits inside a register, then it is always passable in a register.
3. Otherwise, it is not possible to pass `T` in a register.

### Template Parameters

|Name|Kind|Description|
|----|----|-----------|
|`T`|`typename`|The type to determine if it can be passed in a register or not.|

### Data Members

|Data Member|Description|
|----|-----------|
|`static constexpr bool value`|A boolean value which is `true` if `T` is passable in a register and `false` otherwise.|

### Convenience Alias

You also need to write a `constexpr` variable template `is_passable_in_register_v` that is equivalent to the pseudocode `is_passable_in_register<>::value`.

## Hints

* C++20 style overload resolution management with `requires` might be helpful.
* A "trivial type" is a bona fide idea in C++.
* If all else fails, partial specialisation of class templates are your friend.

## Submission

This lab is due on Sunday 23rd April @ 8pm.

Late submissions without [Special Consideration](https://www.student.unsw.edu.au/special-consideration) receive 0.

Submit by pushing your completed work to your main branch on Gitlab.
