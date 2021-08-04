#include <stdio.h>

int numbers[10];

int main(void) {
    int x, i, n_seen;

    n_seen = 0;
    while (n_seen < 10) {
        printf("Enter number: ");
        scanf("%d", &x);

        i = 0;
        while (i < n_seen) {
            if (x == numbers[i]) {
                break;
            }
            i++;
        }

        if (i == n_seen) {
            numbers[n_seen] = x;
            n_seen++;
        }
    }
    printf("10th different number was %d\n", x);

    return 0;
}
