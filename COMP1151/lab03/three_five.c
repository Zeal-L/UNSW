// By Zeal L, September 2020  Third week in COMP1511
// Zid:z5325156
#include<stdio.h>

int main(void){
    int number, counter = 1;
    printf("Enter number: ");
    scanf("%d", &number);
    while (number != counter) {
        if (counter%3 == 0 || counter%5 == 0) {
            printf("%d\n", counter);
        }
        counter++;
    }
    return 0;
}