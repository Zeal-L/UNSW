// By Zeal L, September 2020  fourth week in COMP1511
// Zid:z5325156

// Prints the first n digits of pi, where n is specified 
// by the user

#include<stdio.h>

#define MAX_DIGITS 10

int main(void) {
    int pi[MAX_DIGITS] = {3, 1, 4, 1, 5, 9, 2, 6, 5, 3};
    int number = 0;
    int i = 0;
    printf("How many digits of pi would you like to print? ");
    scanf("%d", &number);
    if (number == 0) {
        printf("\n");
        return 0;
    }
    printf("%d", pi[i]);
    i = 1;
    if (number != 1) printf(".");
    while (i < number) {
        printf("%d", pi[i]);
        i++;
    }
    printf("\n");
    return 0;
}