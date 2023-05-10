#ifndef COMP6771_ORDER_H
#define COMP6771_ORDER_H

#include <iostream>

struct A {
    A() { std::cout << "A"; }
    ~A() { std::cout << "~A"; }
};

struct B: virtual public A {
    B() { std::cout << "B"; }
    ~B() { std::cout << "~B"; }
    A a;
};

struct C: virtual public A {
    C() { std::cout << "C"; }
    ~C() { std::cout << "~C"; }
    B b;
};

struct D: public C, public B {
    D() { std::cout << "D"; }
    ~D() { std::cout << "~D"; }
    C c;
    A a;
};


#endif // COMP6771_ORDER_H
