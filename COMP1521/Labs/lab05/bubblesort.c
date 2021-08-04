// Read 10 numbers into an array
// bubblesort them
// then print them

#include <stdio.h>

int main(void) {
    int i;
    int numbers[10] = { 0 };

    i = 0;
    while (i < 10) {
        scanf("%d", &numbers[i]);
        i++;
    }

    int swapped = 1;
    while (swapped) {
        swapped = 0;
        i = 1;
        while (i < 10) {
            int x = numbers[i];
            int y = numbers[i - 1];
            if (x < y) {
                numbers[i] = y;
                numbers[i - 1] = x;
                swapped = 1;
            }
            i++;
        }
    }

    i = 0;
    while (i < 10) {
        printf("%d\n", numbers[i]);
        i++;
    }
}
