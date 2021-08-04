// print the minimum of two integers
#include <stdio.h>

int main(void) {
    int x, y;

    scanf("%d", &x);
    scanf("%d", &y);

    if (x < y) {
        printf("%d\n", x);
    } else {
        printf("%d\n", y);
    }

    return 0;
}
