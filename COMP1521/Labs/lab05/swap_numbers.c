// Read 10 numbers into an array
// swap any pair of numbers which are out of order
// then print the array

#include <stdio.h>

int main(void) {
    int i;
    int numbers[10] = { 0 };

    i = 0;
    while (i < 10) {
        scanf("%d", &numbers[i]);
        i++;
    }

    i = 1;
    while (i < 10) {
        int x = numbers[i];
        int y = numbers[i - 1];
        if (x < y) {
            numbers[i] = y;
            numbers[i - 1] = x;
        }
        i++;
    }

    i = 0;
    while (i < 10) {
        printf("%d\n", numbers[i]);
        i++;
    }
}
