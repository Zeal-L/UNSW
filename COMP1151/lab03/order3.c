// By Zeal L, September 2020  Third week in COMP1511
// Zid:z5325156
#include<stdio.h>

int main(void){
    int number1 = 0, number2 = 0, number3 = 0;
    printf("Enter integer: ");
    scanf("%d", &number1);
    printf("Enter integer: ");
    scanf("%d", &number2);
    printf("Enter integer: ");
    scanf("%d", &number3);
    if (number1 <= number2 && number2 <= number3) {
        printf("The integers in order are: %d %d %d\n", number1, number2, number3);
        return 0;
    }
    if (number1 <= number3 && number3 <= number2) {
        printf("The integers in order are: %d %d %d\n", number1, number3, number2);
        return 0;
    }
    if (number2 <= number1 && number1 <= number3) {
        printf("The integers in order are: %d %d %d\n", number2, number1, number3);
        return 0;
    }
    if (number2 <= number3 && number3 <= number1) {
        printf("The integers in order are: %d %d %d\n", number2, number3, number1);
        return 0;
    }
    if (number3 <= number1 && number1 <= number2) {
        printf("The integers in order are: %d %d %d\n", number3, number1, number2);
        return 0;
    }
    if (number3 <= number2 && number2 <= number1) {
        printf("The integers in order are: %d %d %d\n", number3, number2, number1);
        return 0;
    }
    return 0;
}