# 507: zip++

With C++20 came a great number of additions (concepts, ranges, modules, etc.). Despite all of these benefits, C++20 _still_ doesn't have anything like Python's `zip()`*. `zip()` accepts two ranges and returns a range containing the pairs of corresponding elements, stopping when the shorter range is exhausted.
For example:
```cpp
std::vector<int> i1 = {1, 2, 3};
std::vector<int> i2 = {4, 5};

// Dereferencing the iterator from zip returns a std::pair<int, int>
for (const std::pair<int, int> &p : zip{i1, i2}) {
    std::cout << p.first << " " << p.second << std::endl;
}

Outputs:
1 4
2 5
```

In this activity we shall build up a new `zip` type in `src/zip.h` and/or `src/zip.cpp`, and finally have access to something Python has had access to for _years_.

With the `zip` type comes its iterator, which should be modelled as [a random-access iterator](https://en.cppreference.com/w/cpp/named_req/RandomAccessIterator). Likewise, the `zip` type will _at least_ have to be modelled as [a reversible container](https://en.cppreference.com/w/cpp/named_req/ReversibleContainer).

There is a small client program in `src/zipper.cpp`. You have successfully completed this task when the program compiles and runs without error.

**Note**: you are not allowed to modify `src/zipper.cpp`.

**Implementation Hints**:
- It might be useful to think about how `std::vector`'s iterator works: it is essentially a pointer to the start of the internal buffer, and an index.
- Make sure that the required type aliases are correctly spelt and implemented.
- You will only need to implement a `const_iterator` (though `zip::iterator` should still be available). It should not be possible to modify the elements of the zipped ranges through the iterator.
- Don't overthink the `zip()` functionality: it is rather simple. What is difficult is making sure your custom iterator conforms to the Iterator interface.
- Friendship will likely be necessary.

<br />

\* [std::ranges::zip_view](https://en.cppreference.com/w/cpp/ranges/zip_view) was not in the Standard Library until C++23.

## Submission

This lab is due on Sunday 19th March @ 8pm.

Late submissions without [Special Consideration](https://www.student.unsw.edu.au/special-consideration) receive 0.

Submit by pushing your completed work to your main branch on Gitlab.
