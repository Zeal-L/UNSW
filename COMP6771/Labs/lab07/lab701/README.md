# 701: Rethrow That Log

Often when writing exception-aware code, there are multiple places where a thrown exception needs to be logged (exceptions are, after all, _exceptional_).

C++ offers a a mechanism for both throwing and *re*throwing exceptions. Conveniently, the same keyword `throw` is used for both.

In `src/rethrower.cpp`, there is a small client program that attempts to make a connection to `db_conn` through a helper function called `make_connection`. The issue is that `db_conn::try_connection`, which `make_connection` **uses in its implementation**, doesn't throw the same exception type that `main()` in `rethrower.cpp` is expecting.

Clearly, the author of the `main()` function was expecting that `make_connection` would rethrow any exceptions caught as the description of the original exception. Specifically, if `make_connection` caught an exception in a variable `e`, it should rethrow `e.what()`.

Your task is to complete the `db_conn` and `make_connection` functions according to this behaviour such that `rethrower.cpp` compiles and produces the following output:
```text
Could not establish connection: hsmith is not allowed to login.
Could not establish connection: HeLp ;_; c0mpu73R c@ann0T c0mPut3 0w0
Could not establish connection: HeLp ;_; c0mpu73R c@ann0T c0mPut3 0w0
```
**Note**: each line is terminated with a new line.

You should implement the code in `src/rethrow.cpp`.

There is further documentation of the `db_conn` class and `make_connection` function in `src/rethrow.h`.

**Important**: you are not allowed to modify `src/rethrower.cpp`.

## Submission

This lab is due on Sunday 2nd April @ 8pm.

Late submissions without [Special Consideration](https://www.student.unsw.edu.au/special-consideration) receive 0.

Submit by pushing your completed work to your main branch on Gitlab.
