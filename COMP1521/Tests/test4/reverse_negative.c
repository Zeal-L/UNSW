// Read numbers into an array until a negative number is entered
// then print the numbers in reverse order

#include <stdio.h>

int numbers[1000];

int main(void) {
    int i = 0;
    while (i < 1000) {
        int x;
        scanf("%d", &x);
        if (x < 0) {
            break;
        } else {
            numbers[i] = x;
        }
        i++;
    }

    while (i > 0) {
        i--;
        printf("%d\n", numbers[i]);
    }
}
