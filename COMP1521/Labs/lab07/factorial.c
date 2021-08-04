// Recursive factorial function
// n < 1 yields n! = 1

#include <stdio.h>

int factorial(int);

int main(void) {
    int n = 0;
    printf("Enter n: ");
    scanf("%d", &n);
    int f = factorial(n);
    printf("%d! = %d\n", n, f);
    return 0;
}

int factorial(int n) {
    int result;
    if (n > 1) {
        result = n * factorial(n - 1);
    } else {
        result = 1;
    }
    return result;
}
