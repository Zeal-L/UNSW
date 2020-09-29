// By Zeal L, September 2020  Secend week in COMP1511
// Zid:z5325156
#include<stdio.h>

int main(void){
    
    int number;
    scanf("%d", &number);

    if (number > 0) {
        printf("You have entered a positive number.\n");
    } else if (number == 0) {
        printf("You have entered zero.\n");
    } else {
        printf("Don't be so negative!\n");
    }
    return 0;
}