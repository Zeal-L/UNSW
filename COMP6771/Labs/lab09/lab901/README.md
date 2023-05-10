# 901: Ring Temple

Implement the below `ring` class template specification in `src/ring.h`.

There is a client program in `src/ring.cpp` that uses `ring`. You have successfully completed this lab when this program compiles and produces the following output:
```
Not enough capacity
1 2 3 
42 6771 
Not enough capacity
hello world! 
yet another lazy sunday
```
**Note**: each line is terminated by a newline.

**Note**: you are not allowed to modify `src/ring.cpp`.

## `class ring`

A `ring` is a special data structure usually used for space efficient queues. It is also called a circular buffer. Essentially, a C-style array is used with a `head` and `tail` index to push and pop elements from the queue. When a user pushes an element onto the `ring`, `tail` progresses by 1. If the end of the array is reached, `tail` wraps to the start of the array. Similarly for `head`, each time the user pops an element from the `ring`, `head` is progressed by 1. When the end of the array is reached, `head` wraps around to the start.

To prevent `head` from overlapping `tail`, an extra `size` data member is kept. The added benefit of explicitly keeping track of the size is that we can prevent the user from accidentally popping from the queue when there are no more elements and from pushing onto the queue when the queue is full.

### Template Parameters

|Name|Kind|Description|
|----|----|-----------|
|`T`|`typename`|`T` is the element type of the `ring`.|
|`N`|`std::size_t`|`N` is a `std::size_t` non-type template parameter that denotes the maximum size of the `ring`.|

### Mandatory Private Internal Representation

|Data Member|Description|
|----|-----------|
|`std::size_t head_`|The current next index to pop from.|
|`std::size_t tail_`|The current next index to push into.|
|`std::size_t size_`|The current size of the ring.|
|`T elems_[N]`|The array of elements.|

### (constructor)
```cpp
/* 1 */ ring(std::initializer_list<T> il);

template <typename InputIt>
/* 2 */ ring(InputIt first, InputIt last);
```
1. Initialiser list contructor.
- Pushes all of the elements of `il` into `*this`.
- Throws `std::invalid_argument{"Not enough capacity"}` if `il.size() > N`.

2. Iterator constructor.
- Pushes all of the elements denoted by the range [`first`, `last`) into `*this`.
- Throws `std::invalid_argument{"Not enough capacity"}` if `std::distance(first, last) > N`.

### Member Functions
```cpp
auto push(const T &t) -> void;
```
Pushes a new element into the `ring`.
- Position of where to push denoted in `tail_`.
- May need to wrap `tail_` to the start of the array.
- Has no effect if the queue is full.

```cpp
auto peek() const -> const T&;
```
Return a constant reference to the head of the queue.
- Position of where the head denoted in `head_`.
- Undefined behaviour if called with an empty queue.

```cpp
auto pop() -> void;
```
Pops the head of the queue.
- Position of where to pop denoted in `head_`.
- May need to wrap `head_` to the start of the array.
- Has no effect if the queue is empty.

```cpp
auto size() const -> std::size_t;
```
Returns the size of the queue.

## Deduction Guide

It should be possible to deduce the type and size of a `ring` from the below expression:
```cpp
auto r = ring{1, 2, 3};
```
You must a Class Template Deduction Guide to allow code like this to compile.

## Submission

This lab is due on Sunday 16th April @ 8pm.

Late submissions without [Special Consideration](https://www.student.unsw.edu.au/special-consideration) receive 0.

Submit by pushing your completed work to your main branch on Gitlab.
