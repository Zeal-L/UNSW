// Read numbers into an array until their sum is >= 42
// then print the numbers in reverse order

#include <stdio.h>

int numbers[1000];

int main(void) {
    int i = 0;
    int sum = 0;
    while (sum < 42) {
        int x;
        scanf("%d", &x);
        numbers[i] = x;
        i++;
        sum += x;
    }

    while (i > 0) {
        i--;
        printf("%d\n", numbers[i]);
    }
}
