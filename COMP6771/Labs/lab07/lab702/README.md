# 702: Stack Unwinding

In `src/answers.txt`, write the alternative which most accurately answers the questions below. Each question's answer **must** be on a newline and be one of `a`, `b`, `c`, or `d` (note the lowercase).

1. What is *stack unwinding*?
- a) The process of finding an exception handler, leaving any stack frames in the same state since the OS will automatically reclaim the memory.
- b) The process of examining the stack frame to find any potential errors in our code.
- c) The process of popping stack frames until we find an exception handler for a thrown exception.
- d) The process of printing out to the terminal all the variables that exist in each stack frame as an exception propagates.
  
2. What happens during *stack unwinding*?
- a) Relevant destructors are called on objects on the way out and any exceptions thrown in a destructor (that are not caught and handled in that destructor) cause `std::terminate` to be called.
- b) Each stack frame's memory is passed to `delete` or `free()`, which will invoke the relevant destructors for objects and any exceptions thrown from a destructor cause `std::terminate` to be called.
- c) Relevant destructors are called on objects on the way out and any exceptions thrown in a destructor cause `std::terminate` to be called.
- d) Each stack frame's memory is passed to `delete` or `free()`, which will invoke the relevant destructors for objects and any exceptions thrown from a destructor (that are not caught and handled in that destructor) cause `std::terminate` to be called.

3. What issue can this potentially cause? If an issue is caused, how would we fix it?
- a) No issues are caused: every type has a destructor (even fundamental types like pointers), as required by the ISO C++ Standard.
- b) It could potentially cause an issue, depending on if we use pointers to heap memory. If we don't use pointers, there is no problem, but if we do use pointers, then we must ensure that that pointer is managed by an RAII class (such as `std::unique_pointer`).
- c) If unmanaged resources were created before an exception is thrown, they may not be appropriately released. The solution is to ensure that every resource is owned by a Standard Library container, such as `std::vector`.
- d) If unmanaged resources were created before an exception is thrown, they may not be appropriately released. The solution is to ensure that every resource is owned by an RAII-conformant class.

## Submission

This lab is due on Sunday 2nd April @ 8pm.

Late submissions without [Special Consideration](https://www.student.unsw.edu.au/special-consideration) receive 0.

Submit by pushing your completed work to your main branch on Gitlab.
