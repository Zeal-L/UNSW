#include <stdio.h>
#include <stdlib.h>

#define SERIES_MAX 46

int fibon(int n);

int main(void) {
	int n;
    while (scanf("%d", &n) != EOF && n <= SERIES_MAX) {
        printf("%d\n", fibon(n));
    }
    return EXIT_SUCCESS;
}


int fibon(int n) {
    if (n == 0) {
        return 0;
    } else if (n == 1 || n == 2) {
        return 1;
    } else {
        return fibon(n - 1) + fibon(n - 2);
    }
}

