// Zeal L (abc982210694@gmail.com)
// 2020-10-20 07:53:50
// Sixth week in COMP1511
// Zid:z5325156
#include <stdio.h>

// return the number of "bigger" values in an array (i.e. larger than 99
// or smaller than -99).
int count_bigger(int length, int array[]) {
    // PUT YOUR CODE HERE (you must change the next line!)
    int count_b = 0;
    for (int i = 0; i < length; i++) {
        if (array[i] < -99 || array[i] > 99) {
            count_b++;
        }
    }
    return count_b;
}

// This is a simple main function which could be used
// to test your count_bigger function.
// It will not be marked.
// Only your count_bigger function will be marked.

#define TEST_ARRAY_SIZE 8

int main(void) {
    int test_array[TEST_ARRAY_SIZE] = {141, 5, 92, 6, 535, -89, -752, -3};

    int result = count_bigger(TEST_ARRAY_SIZE, test_array);

    printf("%d\n", result);
    return 0;
}
