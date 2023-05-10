# 508: Iterator Invalidation

In `src/answers.txt`, write the alternative which most accurately answers the questions below. Each question's answer **must** be on a newline and be one of `a`, `b`, `c`, or `d` (note the lowercase).

1. Consider the following code:
```cpp
auto s = std::unordered_set<int>{1, 2, 3};
auto iter = s.find(1);

s.insert(4);

std::cout << *iter << std::endl;
```
Has iterator invalidation happened here, and if so, why?
- a) Yes: inserting into an array-based container always causes iterator invalidation.
- b) No: `std::unordered_set` always keeps its array length as a prime number and, since the next biggest prime after 3 is 7, there is enough space to insert a new element without a rehash.
- c) Possible: if the internal load factor has been exceeded and the elements had to be copied and rehashed into a new array, then all iterators are invalidated.
- d) Yes: `std::unordered_set` always keeps its array length as a prime number and, since the capacity before inserting is equal to the number of elements, it is guaranteed there will be a new array allocation and rehash, invalidating all iterators.

<br />

2. Consider the following code:
```cpp
auto v = std::vector{};
v.reserve(2);
for (auto i = 0; i < 2; ++i) {
    v.push_back(i);
}
auto iter = v.begin();
v.push_back(3);

std::cout << *iter << std::endl;
```
Has iterator invalidation happened here, and if so, why?
- a) Possible: if the capacity of `v` hasn't been reached yet, then there will be no invalidation. Otherwise, there will be.
- b) Yes: we reserved two spaces and filled them all so, at the time of the next push back, a new array will be allocated and all elements moved over, which will invalidate iterators.
- c) No: We ensured there was enough space in the vector when we called `reserve()`.
- d) Possible: irrespective of calls to `reserve()`, almost all implementations of `std::vector` grow geometrically and keep at least twice as much space as they report to via `capacity()`. If the true internal capacity has been reached, then the iterators will be invalidated, otherwise they won't be.

<br />

3. Consider the following code:
```cpp
auto v = std::vector{3, 2, 1};
auto iter = v.begin();
while (iter != v.end() - 1) {
    iter = v.erase(std::find(v.begin(), v.end(), *iter));
}

std::cout << *iter << std::endl;
```
Has iterator invalidation happened here, and if so, why?
- a) No: whilst modifying a vector we're looping over usually is disastrous, we are reassigning the loop variable `iter` every time to ensure it remains valid.
- b) Yes: you should never modify vectors when you loop over them.
- c) Yes: because an iterator separate to `iter` is passed to `v.erase()`, it invalidates `iter`. If, however, we had written `iter = v.erase(iter);`, it would not be invalidated.
- d) Possible: implementors of `std::vector` are free to choose whether or not this specific use-case invalidates iterators, so it depends on which version of the standard library you compile with.


4. Consider the following code:
```cpp
auto s = std::set<int>{1, 2, 3};
auto iter = s.find(3);

s.erase(2);

std::cout << *iter << std::endl;
```
Has iterator invalidation happened here, and if so, why?
- a) No: erasing an unrelated element from a `std::set` has no effect on `iter`.
- b) Yes: `std::set`, as a binary search tree, always rebalances itself after every modification.
- c) Possible: `std::set`, as a red-black tree, may rebalance itself if the erased element is in the ancestry of `iter`.
- d) No: `std::set` only invalidates iterators when it is moved-from (i.e., in code like `auto s2 = std::move(s)`).

## Submission

This lab is due on Sunday 19th March @ 8pm.

Late submissions without [Special Consideration](https://www.student.unsw.edu.au/special-consideration) receive 0.

Submit by pushing your completed work to your main branch on Gitlab.
