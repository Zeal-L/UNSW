//  read numbers until their sum is >= 42, print their sum

#include <stdio.h>

int main(void) {
    int sum = 0;
    while (sum < 42) {
        int x;
        scanf("%d", &x);
        sum = sum + x;
    }
    printf("%d\n", sum);
    return 0;
}
