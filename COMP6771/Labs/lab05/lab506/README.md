# 506: Ropeful

One way we could implement a "rope" class would be to have a vector of strings.

Of course, a rope is logically contiguous, whereas the elements of a vector are disjoint.

With the power of a custom iterator, however, we can bridge the discontinuities and realise our dreams of having a rope-like container in C++!

In `src/rope.h`, you will find the stubs of two classes, `rope`, and its iterator `rope::iter`.

Your task is to complete the `rope` class's implementation so that it models [a reversible container](https://en.cppreference.com/w/cpp/named_req/ReversibleContainer), and also to implement `rope::iter` so that it models [a bidirectional iterator](https://en.cppreference.com/w/cpp/named_req/BidirectionalIterator).

There is a client program in `src/rope_user.cpp` which will give hints as to how the `rope` class is intended to be used. You have successfully completed this activity when this program compiles and runs without error.

**Note**: You are not allowed to modify `src/rope_user.cpp`.

**Implementation Hints:**
- A contiguous view over a vector of strings implies that each "element" of the range is a single `char`.
- It should not be possible to modify the elements of the range through the iterator. Therefore, you only need to implement a `const_iterator`. The type `rope::iterator` should still be available, though.
- Where possible, it is always preferable to delegate to the Standard Library.
- Friendship will likely be necessary.

## Submission

This lab is due on Sunday 19th March @ 8pm.

Late submissions without [Special Consideration](https://www.student.unsw.edu.au/special-consideration) receive 0.

Submit by pushing your completed work to your main branch on Gitlab.
