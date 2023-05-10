
# 105: Evolution: C to C++

Write a C++ program in `src/cat.cpp` that mimics the C program written below.
The program is intended to mimic the behaviour of the UNIX command `cat`.
For each C++ change, think about what advantages C++ provides.

Make sure you check with your tutor that your C++ code is styled according to modern guidelines.

```c
#include <stdio.h>

int main() {
  char buffer[100];
  fgets(buffer, 100, stdin);
  printf("%s", buffer);
  return 0;
}
```