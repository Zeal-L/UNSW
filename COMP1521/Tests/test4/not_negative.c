// read numbers until a non-negative number entered
#include <stdio.h>

int main(void) {
    int x;

    while (1) {
        printf("Enter a number: ");

        scanf("%d", &x);

        if (x < 0) {
            printf("Enter a positive number\n");
        } else {
            printf("You entered: %d\n", x);
            break;
        }
    }

    return 0;
}
