// print the integers between x and y except 13
#include <stdio.h>

int main(void) {
    int x, y;

    scanf("%d", &x);
    scanf("%d", &y);

    int i = x + 1;
    while (i < y) {
        if (i != 13) {
            printf("%d\n", i);
        }
        i = i + 1;
    }

    return 0;
}
