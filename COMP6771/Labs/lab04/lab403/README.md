# 403: Constructing Destruction

In `src/answers.txt`, write the alternative which most accurately answers the questions below. Each question's answer **must** be on a newline and be one of `a`, `b`, `c`, or `d` (note the lowercase).

Consider the following structure:
```cpp
struct object {
    object() {
		std::cout << "ctor ";
	}

	object(const object &) {
		std::cout << "copy-ctor ";
	}

	~object() {
		std::cout << "dtor ";
	}
};
```

1. What is the output of the below code and why?
```cpp
{
    std::cout << "Pointer: ";
    std::list<object *> l;
    object x;
    l.push_back(&x);
}
```
- a) `Pointer: ctor ctor dtor dtor`. `l` is a list of `object`-derived types and `x` is an `object`, so the constructor and destructor for `object` will run for both.
- b) `Pointer: ctor dtor`. Variables are destructed in the reverse-order of definition on the stack, so to prevent a double-free bug, `l`'s single element (the address of `x`) only has the constructor and destructor run for it.
- c) `Pointer: ctor dtor`. The only `object` whose lifetime ends in this code block is `x`, and the list `l` is irrelevant.
- d) `Pointer: ctor ctor dtor dtor`. `l`'s default constructor creates an `object *` instance and a second instance is created when the address of `x` is pushed back. Two constructions implies two destructions.

2. What is the output of the below code and why?
```cpp
{
    std::cout << "\nValue: ";
    std::list<object> l;
    object x;
    l.push_back(x);
}
```
- a) `Value: ctor copy-ctor dtor dtor`. The default constructor of `object` is called when `x` comes into scope and the copy constructor is called when `x` is pushed back into `l`. At the end of scope, `x` is destructed first and, since `l` holds `object`s by value, its single element is destructed second.
- b) `Value: ctor copy-ctor dtor dtor`. `x` is default-constructed and destructed as per usual, but the temporary that is created by passing `x` into `push_back()` is copy-constructed and destructed in that expression.
- c) `Value: ctor copy-ctor copy-ctor dtor dtor dtor`. `x` is default-constructed and destructed as per usual, but the temporary that is created in the call to `l.push_back()` _and_ the resulting element of `l` are copy-constructed and destructed.
- d) `Value: ctor copy-ctor dtor copy-ctor dtor dtor`. `x` is default-constructed and destructed as per usual, but the temporary that is created in the call to `push_back()` has its lifetime end at the end of that expression before it is copied into `l`. At the end of scope, `l`'s single element is also destructed.

## Submission

This lab is due on Sunday 12th March @ 8pm.

Late submissions without [Special Consideration](https://www.student.unsw.edu.au/special-consideration) receive 0.

Submit by pushing your completed work to your main branch on Gitlab.