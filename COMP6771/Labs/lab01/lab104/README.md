# 104: Using and Testing `std::vector`

One of the most widely used containers from the C++ Standard Library is `std::vector`. A vector is a dynamic array that looks after its own memory and allows elements to be inserted, retrieved, compared for equality, etc.

Alot can be done with a vector and the purpose of this exercise is to gain familiarity with its various operations (called _member functions_ or _methods_).

In `fib_vector.cpp`, there is an incomplete implementation of a function that calculates all of the [Fibonacci numbers](https://en.wikipedia.org/wiki/Fibonacci_number) and returns them in a `std::vector<int>` as well as a few failing tests. Write a proper implementation of `fibonacci()` and more tests so that you more become familiar and confident with using a vector (and also with testing!).

Hint: some of the most widely used methods on vectors are:
- `push_back(elem)`: adds an elements to the vector at the end
- `size()`: returns how many elements are currently in the vector
- `empty()`: returns true if and only if `size() == 0` (**N.B.** this does not `clear()` the vector!)
- `at(n)`: get the nth element from the vector. Can also use `[]`.

A full description of these methods can be found [here](https://en.cppreference.com/w/cpp/container/vector).
