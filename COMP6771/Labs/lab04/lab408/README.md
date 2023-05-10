# 408: GLSL++

The Open**GL** **S**hader **L**anguage (GLSL) is a C/C++-like language used to write shader programs that can run on GPUs.

One convenient feature of the GLSL built-in type `vec3` is that you can access its components by various names. For example:
- `v.x`: access the 1st component in `v` as a spatial dimension.
- `v.r`: access the 1st component in `v` as a colour dimension.
- `v.s`: access the 1st component in `v` as a texture dimension.

In all, there are three sets of syntactic sugar:
- `x`, `y`, `z`: for 1st, 2nd, and 3rd componenets of a `vec3`.
- `r`, `g`, `b`: for 1st, 2nd, and 3rd componenets of a `vec3`.
- `s`, `t`, `p`: for 1st, 2nd, and 3rd componenets of a `vec3`.

In `src/vec3.h` and/or `src/vec3.cpp`, complete the below specification.
When you are done, write at least **three** tests in `src/vec3.test.cpp`.

### Public Data Members

| Data Member | Type |
|--------|---------|
| `v.x`<br/>`v.r`<br/>`v.s` | `double`|
| `v.y`<br/>`v.g`<br/>`v.t` | `double`|
| `v.z`<br/>`v.b`<br/>`v.p` | `double`|

`x`, `r`, and `s` should refer to the same data member.
Likewise, `y`, `g`, and `t` should refer to the same data member.
Similarly, `z`, `b`, and `p` should refer to the same data member.

Therefore, `sizeof(vec3) == 3 * sizeof(double)` should be true.

**Hint**: you may find [this page on unions](https://en.cppreference.com/w/cpp/language/union) useful. Particularly, anonymous unions inside of class-types.

### Constructors

```cpp
/* 1 */ vec3();
/* 2 */ vec3(double c);
/* 3 */ vec3(double a, double b, double c);
```
1) Default constructor.
- Initialise this vector to contain 0 in each component.

2) Broadcast Component Constructor.
- Initialise this vector, setting all components to `c`.

**Note**: you must ensure the below code snippet cannot happen:
```cpp
// should fail to compile.
vec3 foo() { return 1.0; }
vec3 v = foo();
```

3) All Component Constructor.
- Initialise this vector so the first component is `a`, the second is `b`, and the third is `c`.

### Copy-control

Your class should be copyable and destructible.

### Member Functions.

None.

Aside from the constructors, `vec3` is intended to be a plain data struct, so it is OK to access its data members directly.

## Submission

This lab is due on Sunday 12th March @ 8pm.

Late submissions without [Special Consideration](https://www.student.unsw.edu.au/special-consideration) receive 0.

Submit by pushing your completed work to your main branch on Gitlab.