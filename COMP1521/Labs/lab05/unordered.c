// Read 10 numbers into an array
// print 0 if they are in non-decreasing order
// print 1 otherwise

#include <stdio.h>

int main(void) {
    int i;
    int numbers[10] = { 0 };

    i = 0;
    while (i < 10) {
        scanf("%d", &numbers[i]);
        i++;
    }

    int swapped = 0;
    i = 1;
    while (i < 10) {
        int x = numbers[i];
        int y = numbers[i - 1];
        if (x < y) {
            swapped = 1;
        }
        i++;
    }

    printf("%d\n", swapped);
}
