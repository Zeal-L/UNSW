// Zeal L (abc982210694@gmail.com)
// 2020-10-13 16:48:34
// Fifth week in COMP1511
// Zid:z5325156
#include <stdio.h>

// swap the values in two integers, given as pointers
void swap_pointers(int *a, int *b) {
    // PUT YOUR CODE HERE (you must change the next line!)
    int c = *a;
    *a = *b;
    *b = c;
}

// This is a simple main function which could be used
// to test your swap_pointers function.
// It will not be marked.
// Only your swap_pointers function will be marked.

int main(void) {
    int first = 1;
    int second = 2;
    
    swap_pointers(&first, &second);
    
    printf("%d, %d\n", first, second);
    return 0;
}
