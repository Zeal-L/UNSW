// Zeal L (abc982210694@gmail.com)
// 2020-11-23 09:20:33
// Zid:z5325156
//
// Print out an array.


#include <stdio.h>
#include <assert.h>

#define MAX_SIZE 1000

void show_array(int size, int array[size]);

// DO NOT CHANGE THIS MAIN FUNCTION
int main(int argc, char *argv[]) {
    // Create the array.
    int array[MAX_SIZE];

    // Get the array size.
    int size;
    printf("Enter array size: ");
    assert(scanf("%d", &size) == 1);
    assert(size > 0);

    // Scan in values for the array.
    printf("Enter array values: ");
    int i = 0;
    while (i < size) {
        assert(scanf("%d", &array[i]) == 1);
        i = i + 1;
    }

    // Print the values.
    show_array(size, array);

    return 0;
}

// This function prints the array in the format
// [1, 2, 3, ...]
void show_array(int size, int array[size]) {
    printf("[");
    for (int i = 0; i < size-1; i++) {
        printf("%d, ", array[i]);
    }
    printf("%d]\n", array[size-1]);
}
