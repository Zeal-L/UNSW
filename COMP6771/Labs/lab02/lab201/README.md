# 201: Definitive Declarations

In `src/answers.txt`, write the alternative which most accurately answers the questions below. Each question's answer **must** be on a newline and be one of `a`, `b`, `c`, or `d` (note the lowercase).


1. Is the line marked (*) a declaration or a definition?
```cpp
int get_age(); // (*)

int main() {

}
```
- a) Declaration
- b) Definition
- c) Neither
- d) Both

2. Is the line marked (*) a declaration or a definiton?
```cpp
int get_age();

int age = get_age(); // (*)
```
- a) Declaration
- b) Definition
- c) Neither
- d) Both

3. Is the line marked (*) a declaration or a definition?
```cpp
int main() {
  auto age = 20; // (*)
}
```
- a) Declaration
- b) Definition
- c) Neither
- d) Both

4. Is the line marked (*) a declaration or a definition?
```cpp
int main() {
  auto age = 20;
  std::cout << age << std::endl; // (*)
}

```
- a) Declaration
- b) Definition
- c) Neither
- d) Both

5. Is the line marked (*) a declaration or a definition?
```cpp
int get_age();

int get_age() { // (*)
  return 6771;
}
```
- a) Declaration
- b) Definition
- c) Neither
- d) Both

## Submission

This lab is due on Sunday 26th February @ 8pm.

Late submissions without [Special Consideration](https://www.student.unsw.edu.au/special-consideration) receive 0.

Submit by pushing your completed work to your main branch on Gitlab.
