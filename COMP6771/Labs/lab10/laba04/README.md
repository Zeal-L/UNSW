# a04: Inferential Declaration

In `src/answers.txt`, write the alternative which most accurately answers the questions below. Each question's answer **must** be on a newline and be one of `a`, `b`, `c`, or `d` (note the lowercase).

1. Consider the following code:
```cpp
int main() {
	int i = 5;
	int &j = i;

	decltype((j)) var = /* initialiser */;
}
```
What is the type of `var` and why?
- a) `int`: `j` is a reference to an `int` and when used in expressions its value is copied into a temporary of type `int`.
- b) `int &`: `j` is an `int&` and `(j)` is equivalent to `j` in every context.
- c) `int &`: `j` is an `int&` and a parenthesised expression of an `int&` is still an `int&`.
- d) `int &&`: `j` is an `int&` and a parenthesised expression of an `int&` is an `int&&`.

2. Consider the following code:
```cpp
int main() {
	int i = 5;
	decltype((std::move(i)) var = /* initialiser */;
}
```
What is the type of `var` and why?
- a) `int &`: `decltype`, when used with parentheses, always is an lvalue.
- b) `int`: it is illegal to have stack-allocated variables as rvalue references -- only function parameters can have this type.
- c) `int &&`: `decltype` preserves the value category of its argument, and `std::move()` converts its argument to an rvalue reference.
- d) `int &`: `decltype`, when used with parentheses, always is an lvalue. Thus, `decltype(std::move(i))` is equivalent to `decltype (int & &&)`, which collapses to `int&`.

3. Consider the following code:
```cpp
int main() {
	decltype((5)) var = /* initialiser */;
}
```
What is the type of `var` and why?
- a) `int`: `decltype` preserves the value category of its argument, and integer literals have type `int`. The parentheses have no effect on literals.
- b) `int &`: There is a special case with `decltype` that states if a literal is used with parentheses then memory must be allocated for an lvalue reference. If this wasn't the case, `var` would be a dangling reference to an expired value.
- c) `int &`: `decltype`, when used with parentheses, always is an lvalue. Thus, `var` is `int&`.
- d) `(int&&) &`: `int` literals have type `int&&` and `(&)` is deduced as an lvalue. Altogether `(int &&) &`.

4. Consider the following code:
```cpp
constexpr auto foo(const auto &f) -> decltype(auto) {
	if constexpr (sizeof(f) != sizeof(void *)) {
		auto val = f;
		return val;
	} else {
		auto val = *f;
		return val;
	}
}

int main() {
	constexpr int arr[3] = {};
	auto var = foo(arr);
}
```
What is the type of `var` and why?
- a) `const int(&)[3]`: The type of `f` is `const int(&)[3]`. This means that `sizeof(f)` will be unequal to `sizeof(void*)` and we enter the first `if` branch. Here, we are simply returning a reference we were passed, thus `const int(&)[3]`.
- b) `const int *`: The type of `f` is `const int(&)[3]`, and `foo` returns a reference to an array from the `val` lvalue. Because `var` is declared as `auto`, the return array reference decays into a pointer inside of the `main()` function and so `var` is a `const int *`.
- c) `const int(&&)[3]`: Because an lvalue to `arr` was passed to `foo`, `f`'s type is deduced to be `const int (&&)[3]`. We then copy this reference into `val` and return it from `foo`. This rvalue reference is finally stored into `var`, hence `const int(&&)[3]`.
- d) `const int *`: The type of `f` is `const int(&)[3]`, and the assignment `val = f` causes `f` to decay to a pointer. We then simply return a pointer, which is copied into `var`.

## Submission

This lab is due on Sunday 23rd April @ 8pm.

Late submissions without [Special Consideration](https://www.student.unsw.edu.au/special-consideration) receive 0.

Submit by pushing your completed work to your main branch on Gitlab.
