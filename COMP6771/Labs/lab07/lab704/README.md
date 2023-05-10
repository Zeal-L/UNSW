# 704: Intelligent Pointing

In `src/answers.txt`, write the alternative which most accurately answers the questions below. Each question's answer **must** be on a newline and be one of `a`, `b`, `c`, or `d` (note the lowercase).

1. Consider the following code which currently does not use smart pointers:
```cpp
#include <thread>

void *get_memory_resource();

void very_long_lived_operation(void *data);

std::vector<std::jthread> make_threads() {
    void *data = get_unique_memory_resource();

    // Start three threads.
    // These all execute at the same time!!
    // All need access to the data
    // Don't know which one will finish first.
    return {
        std::jthread{[data](){ very_long_lived_operation(data); }},
        std::jthread{[data](){ very_long_lived_operation(data); }},
        std::jthread{[data](){ very_long_lived_operation(data); }},
    };
} // data (the pointer) went out of scope

int main() {
    // when this vector goes out of scope, the
    // program will wait for all of the threads to finish!
    auto threads = make_threads();
}
```
Which would be the appropriate smart pointer or smart pointers to replace the raw pointers with in this case and why?
- a) All pointers `std::weak_ptr`: The three threads are contending with each other, and we need to break the tie of which thread has access to the data.
- b) All pointers `std::shared_ptr`: each thread logically "owns" `data` and we cannot be sure which thread will finish first.
- c) First `std::jthread` uses a `std::unique_ptr`, the other two use `void *`: By designating one thread as the owner of the memory and the other two as observers, we ensure that `data` will never go out of scope.
- d) No change: this code is fine as it is.

2. Consider the following code which currently does not use smart pointers:
```cpp
struct node {
    struct node *parent; // go up the tree
    struct node *my_left_child; // go left of the tree
    struct node *my_right_child; // go right of the tree
};
```
Which would be the appropriate smart pointer or smart pointers to replace the raw pointers with in this case and why?
- a) All pointers `std::shared_ptr`: As a parent node, we should own the memory for the left and right child, and we need to ensure our parent outlives us.
- b) Two children pointers `std::shared_ptr`, parent pointer is `std::weak_ptr`: As a parent node, we should own the memory for the left and right child, and we need to ensure we outlive our parent. Another `std::shared_ptr` would cause a cycle, so `weak_ptr` is the better choice for it.
- c) Two children pointers `std::unique_ptr`, parent pointer is `struct node *`: As a parent node, we should own the memory for the left and right child, but need only observe our parent node. Some other node owns its memory, or it is null if we are the root node.
- d) No change: this code is fine as it is.

3. Consider the following code which currently does not use smart pointers:
```cpp
class vec {
public:
    vec(int size) : data_{new int[]{size}} {}

    ~vec() { delete[] data_; }

    const int *data() const { return data_; }
private:
    int *data_;
};
```
Which would be the appropriate smart pointer or smart pointers to replace the raw pointers with in this case and why?
- a) All pointers are `std::shared_ptr`: a future user of this class may need to take control of the underlying data and only `std::shared_ptr` will let them do that.
- b) `data_` is a `std::unique_ptr`, `data()` is `const int *`: we have exclusive ownership of `data_`, and this aligns with the semantics of `std::unique_ptr` perfectly. `data()` returns a `const int *`, so a user will not be able to modify the underlying elements and break encapsulation.
- c) All pointers are `std::unique_ptr`: A user may accidentally modify an element of the underlying data from `data()`, so to prevent this, we should deep-copy `data_` into another `std::unique_ptr`.
- d) No change: this code is fine as it is.


## Submission

This lab is due on Sunday 2nd April @ 8pm.

Late submissions without [Special Consideration](https://www.student.unsw.edu.au/special-consideration) receive 0.

Submit by pushing your completed work to your main branch on Gitlab.
