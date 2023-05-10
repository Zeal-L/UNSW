# 402: Namespacing Out

In `src/namespaced.cpp`, we have provided the below `main()` function:
```cpp
int main() {
    namespace spaceland = comp6771;

    // should be an alias for std::vector.
    auto v = spaceland::vector{6771};
    
    // name: earth, position from sun: 3
    // a planet is a kind of 
    auto earth = spaceland::planet{"earth", 3};

    // should produce an object with the same type as the "earth" variable above.
    auto old_earth = spaceland::planets::terrestrial{"earth", 3};

    std::cout << v[0] << std::endl;
    std::cout << earth.name << std::endl;
    std::cout << old_earth.pos << std::endl;
}
```

In `src/namespaced.h`, implement the rest of the missing namespace functionality such that this code compiles and produces this output (note the newline at the end):
```txt
6771
earth
3
```
There is a plain-old-data struct in `src/namespaced.h` that may be used as a `planet` type.

**Note**: you are not allowed to modify `src/namespaced.cpp`.

**Hint**: it does not matter how you implement the namespaces in the header file -- if your code compiles and produces the above output, then it is correct.

## Submission

This lab is due on Sunday 12th March @ 8pm.

Late submissions without [Special Consideration](https://www.student.unsw.edu.au/special-consideration) receive 0.

Submit by pushing your completed work to your main branch on Gitlab.
