// Read a number n and print the first n tetrahedral numbers
// https://en.wikipedia.org/wiki/Tetrahedral_number

#include <stdio.h>

int main(void) {
    int i, j, n, total, how_many;

    printf("Enter how many: ");
    scanf("%d", &how_many);

    n = 1;

    while (n <= how_many) {
        total = 0;
        j = 1;

        while (j <= n) {
            i = 1;
            while (i <= j) {
                total = total + i;
                i = i + 1;
            }
            j = j + 1;
        }
        printf("%d\n", total);
        n = n + 1;
    }
    return 0;
}
