# 102: Printing Sums

`<iostream>` contains an object called `std::cin`, which we can use to read in from the character
input (i.e. the keyboard), like so.

```cpp
auto i = 0;
if (std::cin >> i) {
  std::cout << "Value of i: " << i << '\n';
} else {
  std::cerr << "Something went wrong while reading an integer!\n";
}
```

Write a program in `src/add_numbers.cpp` that reads in two integers and prints out their sum to standard output.