#include <stdio.h>
#define TEST_ARRAY_SIZE 100

// Return the largest number in a 2D square array
// with sides of length side_length.
int array_max(int array[TEST_ARRAY_SIZE][TEST_ARRAY_SIZE], int side_length) {
    int counter = 0;
    for (int i = 0; i < side_length; i++) {
        for (int j = 0; j < side_length; j++) {
            if (counter <= array[i][j]) {
                counter = array[i][j];
            }
        }
    }
    return counter;
}

// This is a simple main function which could be used
// to test your array_max function.
// It will not be marked.

int main(void) {
    int test_array[TEST_ARRAY_SIZE][TEST_ARRAY_SIZE] = {
        { 1,    2,   3,    4  },
        {-1,  -11, -111, -111},
        { 0,   0,   0,    0  },
        { 22, -22,  2,    2  }
    };

    int result;

    result = array_max(test_array, 1);
    printf("Largest value in 1x1 array: %d\n", result);

    result = array_max(test_array, 2);
    printf("Largest value in 2x2 array: %d\n", result);

    result = array_max(test_array, 3);
    printf("Largest value in 3x3 array: %d\n", result);

    result = array_max(test_array, 4);
    printf("Largest value in 4x4 array: %d\n", result);

    return 0;
}
