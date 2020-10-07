// By Zeal L, September 2020 fourth week in COMP1511
// Zid:z5325156

#include<stdio.h>

int main(void) {
    int order = 0, number = 0, power = 0;
    printf("Enter instruction: ");
    while (scanf("%d", &order) == 1) {
        if (order == 1) {
            scanf("%d", &number);
            printf("%d", number * number);
            number = 0;
        } else if (order == 2) {
            scanf("%d%d", &number, &power);
            int counter = 2;
            int save_number = number;
            while (counter <= power) {
                number = number * save_number;
                counter++;
            }
            printf("%d", number);
        } else return 0;
        printf("\nEnter instruction: ");
    }
    return 0;
}