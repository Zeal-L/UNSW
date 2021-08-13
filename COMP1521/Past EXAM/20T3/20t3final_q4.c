// COMP1521 20T3 final exam Q4 C reference

// print low - high

#include <stdio.h>

int main(void) {
    int low = 0;
    int high = 100;
    while (low < high) {
        int x;
        scanf("%d", &x);
        low = low + x;
        high = high - x;
    }
    printf("%d\n", low - high);
    return 0;
}
