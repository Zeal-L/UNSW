// print a square of asterisks
#include <stdio.h>

int main(void) {
    int x;

    scanf("%d", &x);

    int i = 0;
    while (i < x) {
        int j = 0;
        while (j < x) {
            printf("*");
            j = j + 1;
        }
        i = i + 1;
        printf("\n");
    }

    return 0;
}
