# 106: Catch2 Syntax

In `src/answers.txt`, write the alternative which most accurately answers the questions below. Each question's answer **must** be on a newline and be one of `a`, `b`, `c`, or `d` (note the lowercase).


1. What is a `TEST_CASE`?
- a) A `TEST_CASE` is a uniquely-named testing scope that must contain every test we write about our program.
- b) A `TEST_CASE` is a fancy macro that has no effect in "real" code.
- c) A `TEST_CASE` is a uniquely-named testing scope that will keep track of all the `CHECK`s and `REQUIRE`s that pass or fail.
- d) A `TEST_CASE` is a macro where only compile-time evaluable assertions about our code can be written.


2. What is a `CHECK`? In what way, if any, is it different to `assert()`?
- a) `CHECK` and `assert` are both macros and do the exact same thing.
- b) `CHECK` and `assert` are both macros, but a `CHECK` will evaluate an expression and report it if it's false whereas `assert` will crash the program.
- c) `CHECK` is a function that suggests a fact about our code should be true, but `assert` enforces it.
- d) `CHECK` records the failure of an assertion but does nothing about it and is entirely unrelated to `assert`.

3. What is a `REQUIRE`? In what way, if any, is it different to `assert()`?
- a) `REQUIRE` evaluates an expression and crashes the program if it is false but `assert` will report it to the user.
- b) `REQUIRE` and `assert` both evaluate expressions and terminate the currently executing test if false.
- c) `assert` and `REQUIRE` both evaluate expressions, but only `assert` has an effect if the expression is false.
- d) `REQUIRE` evalutes an expression and if false will terminate the currently executing test and move onto the next one. It is entirely unrelated to `assert`.

4. What are `SECTION` blocks in Catch2?
- a) `SECTION` blocks are ways to divide testing logic in `TEST_CASE`s. Any state changes in a `SECTION` are not reflected in `SECTION`s at the same level.
- b) `SECTION` blocks are a way to break up long tests and have little use other than that.
- c) `SECTION`s are unique testing scopes that can only contain `TEST_CASE`s.
- d) `SECTION`s are part of Behaviour Driven Development and group together `SCENARIO`s.


5. What goes between the parentheses in `TEST_CASE`s and `SECTION`s?
- a) The function or class name that is currently being tested.
- b) A succinct and insightful description in plain language of the code under test.
- c) A description that matches a similarly-worded comment directly above the `TEST_CASE`/`SECTION`.
- d) A note for future readers of your code about what you were thinking at the time of writing this test.
