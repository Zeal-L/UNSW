# 804: Static Dynamo

In `src/answers.txt`, write the alternative which most accurately answers the questions below. Each question's answer **must** be on a newline and be one of `a`, `b`, `c`, or `d` (note the lowercase).

Consider the 
```cpp
#include <iostream>

struct banana {
    virtual void f() {
		std::cout << "banana ";
	}
};

struct door : banana {
	void f() override {
		std::cout << "door ";
	}
};

int main() {
	banana b;
	door d;
	b = d;
	banana &bref = dynamic_cast<banana&>(b);
	door &dref = d;
	banana &dbref = dynamic_cast<banana&>(d);
	b.f();
	d.f();
	bref.f();
	dref.f();
	dbref.f();
}
```

1. For each of `bref`, `dref`, and `dbref`: by the end of the program, what is this variable's static and dynamic type?
- a)
    - `bref`: static: `door&`, dynamic: `banana&`
    - `dref`: static: `banana&`, dynamic: `door&`
    - `dbref`: static: `door&`, dynamic: `door&`
- b)
    - `bref`: static: `door&`, dynamic: `banana&`
    - `dref`: static: `door&`, dynamic: `door&`
    - `dbref`: static: `door&`, dynamic: `banana&`
- c)
    - `bref`: static: `banana&`, dynamic: `door&`
    - `dref`: static: `door&`, dynamic: `door&`
    - `dbref`: static: `banana&`, dynamic: `door&`
- d)
    - `bref`: static: `banana&`, dynamic: `banana&`
    - `dref`: static: `door&`, dynamic: `door&`
    - `dbref`: static: `banana&`, dynamic: `door&`

2. Is there anything wrong with the assignment `b = d`?
- a) Yes: we have not defined `operator=` for `banana`.
- b) Yes: since `b` is a `banana`, assigning `d` to it will cause `d`'s `door` half to be sliced off. This is the object slicing problem.
- c) No: this code is perfectly legal code.
- d) Maybe: since `sizeof(banana) == sizeof(door)`, the result of this expression depends on the version of the compiler.

3. In general, how is the object-slicing problem avoided?
- a) It cannot be avoided: C++'s value semantics preclude this possibility.
- b) Only use `std::unique_ptr` in code that uses polymorphic objects.
- c) When dealing with polymorphic objects, always make sure when the static and dynamic types don't align to use either a pointer or a reference.
- d) Make sure the size of polymorphic classes is always the same so that even if slicing occurs, there are no side-effects.

## Submission

This lab is due on Sunday 9th April @ 8pm.

Late submissions without [Special Consideration](https://www.student.unsw.edu.au/special-consideration) receive 0.

Submit by pushing your completed work to your main branch on Gitlab.
