// Sieve of Eratosthenes
// https://en.wikipedia.org/wiki/Sieve_of_Eratosthenes
#include <stdio.h>
#include <stdint.h>

uint8_t prime[1000];

int main(void) {
    int i = 0;
    while (i < 1000) {
        prime[i] = 1;
        i++;
    }

    i = 2;
    while (i < 1000) {
        if (prime[i]) {
            printf("%d\n", i);
            int j = 2 * i;
            while (j < 1000) {
                prime[j] = 0;
                j = j + i;
            }
        }
        i++;
    }
    return 0;
}
