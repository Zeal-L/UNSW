# 703: Stuck In The Matrix

Implement the following class specification in `src/matrix.h` and/or `src/matrix.cpp`.

You will also need to write at least **five** tests in `src/matrix.test.cpp` to ensure your code is robust and correct.

### `class matrix`

A dynamic 0-indexed matrix class that supports *m* x *n* rows and columns respectively.

Internally, the matrix is stored as a flat array of `int`s. It is implementation-defined whether this matrix is stored in either [row-major or column-major order](https://en.wikipedia.org/wiki/Row-_and_column-major_order).

### Required Private Internal Representation

|Name|Type|Description|
|-----|-----|-----|
|data_|`std::unique_ptr<int[]>`|A unique pointer to an array of heap-allocated `int`s.|
|n_rows_|`std::size_t`|The number of rows of this matrix.|
|n_cols_|`std::size_t`|The number of columns of this matrix.|

### (constructors)

```cpp
/* 1 */ matrix() noexcept;
/* 2 */ matrix(std::initializer_list<std::initializer_list<int>> il);

/* 3 */ matrix(const matrix &other);
/* 4 */ matrix(matrix &&other);
```
1. **Default constructor**.
- Constructs a 0 x 0 matrix.
- No heap allocation should occur.

2. **Initialiser list constructor**.
- Constructs a matrix where the rows and columns are deduced from the nested initialiser list.
- The outer initializer list contains the rows.
- The inner initializer list contains the columns.
- The number of rows should be deduced from `std::distance(il.begin(), il.end())`.
- The number of columns should be deduced from `std::distance(il.begin()->begin(), il.begin()->end())`
  - I.e., the first element of `il` should dictate the number of columns.
- If all the columns are not the same length, throws a `std::logic_error` with message `Columns are not equal length`.
- Can assume there is at least one `int` in the initialiser list.

3. **Copy-constructor**.
- Constructs a matrix through deep-copying `other`.
- After construction, `*this == other` should be true.

4. **Move-constructor**.
- Constructs a matrix through stealing the internals of `other`.
- Afterwards, `other.dimensions() == std::make_pair(0, 0)` should be true.
  - `other.data_ == nullptr` should be true.

### Operator Overloads.
```cpp
matrix &operator=(const matrix &other);
```
**Copy-assignment operator**.
- Frees the current matrix's data
- Does a deep copy of `other`'s data.
- After the assigment, `*this == other` should be true.
- Does nothing in the case of self-assignment.

```cpp
matrix &operator=(matrix &&other) noexcept;
```
**Move-assignment operator**.
- Frees the current matrice's data.
- Steals the internals of `other`.
- Afterwards, `other.dimensions() == std::make_pair(0, 0)` should be true.
  - `other.data_ == nullptr` should be true.
- Does nothing in the case of self-assignment.

```cpp
int &operator()(std::size_t r, std::size_t c);
const int &operator()(std::size_t r, std::size_t c) const;
```
**Gets an element from the matrix**.
- If either `r` or `c` are outside the bounds of the matrix, throws a `std::domain_error` with message `(<r>, <c>) does not fit within a matrix with dimensions (<n_rows_>, <n_cols_>)`, where `<var>` is replaced with the actual value of that variable.

```cpp
bool operator==(const matrix &rhs) const noexcept;
```
**C++20 Equality operator**.
- For all `0 <= i < n_rows_` and all `0 <= j < n_cols_`, two matrices are equal if and only if:
  - `lhs(i, j) == rhs(i, j)`.
- This implies two matrices are only equal if their dimensions match and each element is equal.

### Member Functions.
```cpp
std::pair<std::size_t, std::size_t> dimensions() const noexcept;
```
Returns a {n_rows, n_cols} pair.

```cpp
const int *data() const noexcept;
```
Returns a pointer to the underlying data.

### Other Notes.
- You are not allowed to add or remove or in any way modify the spec.

## Submission

This lab is due on Sunday 2nd April @ 8pm.

Late submissions without [Special Consideration](https://www.student.unsw.edu.au/special-consideration) receive 0.

Submit by pushing your completed work to your main branch on Gitlab.
