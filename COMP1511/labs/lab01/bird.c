// Demo Program showing output
// Zeal Liang, September 2020

#include <stdio.h>

int main (void) {
    printf("  ___\n ('v')\n((___))\n ^   ^\n");

    int i = 1;
    printf("%d\n", (++i)+(++i));
    // ++i;    // i = 2
    // ++i;    // i = 3
    // i + i;  // 输出6

    printf("%d\n", (i++)+(i++)+(++i)+(++i));
    printf("%d\n", i);
    return 0;
}
