// By Zeal L, September 2020  fourth week in COMP1511
// Zid:z5325156

#include<stdio.h>

#define MAX_DIGITS 10

int main(void) {
    int input [100] = {0};
    int counter = 0;
    printf("Enter numbers forwards: \n");
    while (counter <= 100 && scanf("%d", &input[counter]) == 1) {
        counter++;
    }
        printf("Reversed: \n");
        counter -= 1;
    while (counter >= 0) {
        printf("%d\n", input[counter]);
        counter--;
    }

    return 0;
}