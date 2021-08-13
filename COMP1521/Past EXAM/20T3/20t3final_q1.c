// COMP1521 20T3 final exam Q1 C reference

// print (x + y) * (x - y)

#include <stdio.h>

int main(void) {
    int x, y;

    scanf("%d", &x);
    scanf("%d", &y);
    printf("%d\n", (x + y) * (x - y));

    return 0;
}
