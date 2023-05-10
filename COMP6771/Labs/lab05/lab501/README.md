# 501: Booked Out

Implement the below specification in `src/book.h` and/or `src/book.cpp`.

You should also should write at least **three** tests in `src/book.test.cpp`.

### Member Functions

```cpp
book(const std::string &name, const std::string &author, const std::string &isbn, double price);
```
Constructor.
- Accepts strings representing the name, author, and isbn of this book, and a double denoting the price.
- Should initialise private internal variables of corresponding type with these values.

<br />

```cpp
explicit operator std::string() const;
```
Explicit type conversion operator to `std::string`.
- Should convert `*this` to a string.
- Format is: `<author>, <name>`.

For example:
```cpp
book b = {"Tour of C++11", "Bjarne Stroustrup", "0123456789X", 9000}; // very valuable book
std::string s = static_cast<std::string>(b);
std::cout << s;
```
Output: `Bjarne Stroustrup, Tour of C++11`

<br />

```cpp
const std::string &name() const;
```
Returns the name of this book.

<br />

```cpp
const std::string &author() const;
```
Return the author of this book.

<br />

```cpp
const std::string &isbn() const;
```
Return the ISBN of this book.

<br />

```cpp
const double &price() const;
```
Return the price of this book.

### Non-member Functions
```cpp
bool operator==(const book &lhs, const book &rhs);
```
Equality operator overload.
- Compares two books for equality.
- Two books are equal if they have the same ISBN.

<br />

```cpp
bool operator!=(const book &lhs, const book &rhs);
```
Inequality operator overload.
- Compares two books for inequality.
- **Hint**: you may be able to reuse another piece of code here...

<br />

```cpp
bool operator<(const book &lhs, const book &rhs);
```
Less-than relation operator overload.
- Orders books according to ISBN.
- `lhs < rhs` iff `lhs.isbn < rhs.isbn`.

<br />

```cpp
std::ostream &operator<<(std::ostream &os, const book &b);
```
Output stream operator overload.
- Prints out `b`'s details to `os`.
- Should be in the format: `<name>, <author>, <isbn>, $<price>`
- Price, when printed, should be rounded to two decimal places.

For example:
```cpp
book b = {"Tour of C++11", "Bjarne Stroustrup", "0123456789X", 9001}; // extremely valuable book
std::cout << b;
```
Output: `Tour of C++11, Bjarne Stroustrup, 0123456789X, $9001.00`


## Submission

This lab is due on Sunday 19th March @ 8pm.

Late submissions without [Special Consideration](https://www.student.unsw.edu.au/special-consideration) receive 0.

Submit by pushing your completed work to your main branch on Gitlab.
