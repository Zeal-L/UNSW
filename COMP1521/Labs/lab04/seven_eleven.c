// Read a number and print positive multiples of 7 or 11 < n

#include <stdio.h>

int main(void) {
    int number, i;

    printf("Enter number: ");
    scanf("%d", &number);

    i = 1;
    while (i < number) {
        if (i % 7 == 0 || i % 11 == 0) {
            printf("%d\n", i);
        }
        i = i + 1;
    }

    return 0;
}
