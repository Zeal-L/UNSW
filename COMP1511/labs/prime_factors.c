#include <stdio.h>
#include <stdlib.h>

int main(void) {
    int num;
    int i = 2;
    printf("Enter number: ");
    scanf("%d", &num);
    //judge if it is prime
    int prime = 0;
    while (i < num) {
        if (num % i == 0)
            prime++;
        i++;
    }
    if (prime == 0) {
    //if num is prime
        printf("%d is prime\n",num);                
    } else {
    //if num not prime 
        i = 2;   
        printf("The prime factorization of %d is:\n", num);
        int n = num;
        while (i <= n) {
            while (n%i == 0) {
                n = n/i;
                if (n == 1)
                    printf("%d ", i);
                else
                    printf("%d * ", i);   
            }
            i++;
        }
        printf("= %d\n", num);
    }
    return EXIT_SUCCESS;
}
