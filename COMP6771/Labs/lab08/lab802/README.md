# 802: Visualising Tables

In `src/answers.txt`, write the alternative which most accurately answers the questions below. Each question's answer **must** be on a newline and be one of `a`, `b`, `c`, or `d` (note the lowercase).

Consider the following class hierarchy:
```cpp
struct A {
    virtual void f(int) {}
    virtual void g() {}
    void a() {}
    virtual ~A() {}
};

struct B : A {
    void f(int) override {}
    virtual void h(int) final {}
    static void b() {}
};

struct C : B {
    virtual void f(int, int) {}
    virtual void x() {}
    void h(int) override {}
};
```
Below is a representation of the incomplete vtables for `A`, `B`, and `C`:
> |A|B|C|
> |-|-|-|
> |A::f(int)|B::f(int)|**$**|
> |**!**|**@**|C::f(int, int)|
> |~A()|~B()|~C()|
> |A::g()|**#**|**%**|
> |-|B::h()|A::g()|
> |-|-|C::x()|
> |VTABLE END|VTABLE END|VTABLE END|
**Note 1**: `-` denotes an empty slot: nothing is meant to be there.

**Note 2**: This is not necesarily how a `vtable` would be created by the compiler.

1. In the slot marked **!**, what would be the most appropriate entry and why?
- a) `A::A()`: The constructor needs to be `virtual` so that derived classes and initialise their `A` subobject.
- b) `A::a()`: it is the only remaining function not in the vtable.
- c) `A::a()`: Once one method is made `virtual`, all methods should be `virtual` as a matter of good code style.
- d) Nothing: none of the above.

2. In the slot marked **@**, what would be the most appropriate entry and why?
- a) `B::b()`: this is the only method not yet listed in the `B`'s vtable.
- b) `A::~A()`: In order for `B::~B()` to function correctly, `A::~A()` also needs to be in `B`'s vtable.
- c) `B::g()`: any `virtual` method of the parent, if not explicitly overrided, has an implicit override with a default implementation that simply calls the parent's version of the method.
- d) Nothing: none of the above. 

3. In the slot marked **#**, what would be the most appropriate entry and why?
- a) `A::g()`: `B` has not explicitly overridden this method from `A`, so it inherits `A`'s `virtual` implementation.
- b) `B::g()`: any `virtual` method of the parent, if not explicitly overrided, has an implicit override with a default implementation that simply calls the parent's version of the method.
- c) `B::b()`: though it is `static`, by putting this method into `B`'s vtable, it will be able to be overridden by derived classes.
- d) Nothing: none of the above. 


4. In the slot marked **$**, what would be the most appropriate entry and why?
- a) `C::f(int)`: `C` has overriden `A::f(int)`.
- b) `C::f(int)`: `C` has overriden `B::f(int)`.
- c) `B::f(int)`: `B` explicitly overrode `A::f(int)`, but `C` has not explicitly overridden `B::f(int)`.
- d) Nothing: none of the above. 


5. In the slot marked **%**, what would be the most appropriate entry and why?
- a) `C::h(int)`: (despite the compilation error) though `B` has marked this method as `final`, the `override` specifier overrules this and successfully allows `C` to override `B::h(int)`.
- b) `C::h(int)`: This code does not compile because `C` has not explicitly added a `virtual` destructor.
- c) `B::h(int)`: (despite the compilation error) `B` has marked this method as `final`, meaning it cannot be further overridden by derived classes.
- d) Nothing: none of the above. 


## Submission

This lab is due on Sunday 9th April @ 8pm.

Late submissions without [Special Consideration](https://www.student.unsw.edu.au/special-consideration) receive 0.

Submit by pushing your completed work to your main branch on Gitlab.
