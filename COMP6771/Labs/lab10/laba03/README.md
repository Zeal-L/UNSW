# a03: Conception

Templates are the primary way of creating generic types and algorithms in C++. Prior to C++20, templates were effectively [duck-typed](https://en.wikipedia.org/wiki/Duck_typing) i.e. if a type appeared to have all of the requirements needed by the template, no error would be generated. Conversely, if a type _didn't_ didn't satisfy the requirements of a template, an error wouldn't be generated until much after point-of-use of the template, resulting in infamously cryptic messages by the compiler.

C++20 brought Concepts, which allow for systematic and formal checking of type requirements needed by templates.

In this exercise we will explore how to create a concept modelling an `animal`. Animals should be able to:
- have a member function called `cry()`, which returns that animal's unique cry as a string i.e. "woof" for a dog, "nyaa" for a Japanese cat, "quack" for a duck, etc.
- have a member type called `name_type` which is a `const char[8+3]`.
- be "regular".

Not all types meet these requirements. For instance, a robot is not an animal because when it cries, nothing happens!

Your task is to implement the below specification in `src/conception.h`.

There is a client program in `src/conception.cpp` that uses ring. You have successfully completed the task when this program compiles and produces the following output:
```cpp
nyaa
woof
quack
robot cry silently
```
**Note**: each line is terminated by a newline.

**Note**: you are not allowed to modify `src/conception.cpp`.

## `concept animal`

The `animal` concept imposes the following logical conjunction of requirements on its template type parameter `A`:
1. `A` must be "regular".
    - **Hint**: regular is a bona fide idea in C++.
2. `A::name_type` must be publically available and be equivalent to `const char [8+3]`.
3. `A::cry()` must:
    - be a publically callable member function
    - be callable by an object of type `const A`.
    - return a `std::string`.

## Other Classes.

You are free to implement `dog`, `neko`, `duck`, and `robot` in any way you like so long as the supplied program compiles and produces the aforementioned output.

## Submission

This lab is due on Sunday 23rd April @ 8pm.

Late submissions without [Special Consideration](https://www.student.unsw.edu.au/special-consideration) receive 0.

Submit by pushing your completed work to your main branch on Gitlab.
