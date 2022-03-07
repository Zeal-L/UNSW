// By Zeal L, September 2020 Secend week in COMP1511
// Zid:z5325156
#include<stdio.h>

int main(void){
    int year;
    printf("Enter year: ");
    scanf("%d", &year);
    int check_1 = year % 100;
    int check_2 = year % 4;
    int check_3 = year % 400;
    if (check_1 == 0) {
        if (check_3 == 0) {
            printf("%d is a leap year.\n", year);
        } else {
            printf("%d is not a leap year.\n", year);
        }
    } else if (check_2 == 0) {
        printf("%d is a leap year.\n", year);
    } else{
        printf("%d is not a leap year.\n", year);
    }
    return 0;
}