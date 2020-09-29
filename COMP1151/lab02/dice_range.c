// By Zeal L, September 2020 Secend week in COMP1511
// Zid:z5325156
#include<stdio.h>

int main(void){
    
    int sides;
    int dice;
    double average;
    printf("Enter the number of sides on your dice: ");
    scanf("%d", &sides);
    printf("Enter the number of dice being rolled: ");
    scanf("%d", &dice);
    
    if (sides > 0) {
        if (dice > 0) {
            printf("Your dice range is %d to %d. \n", dice, sides * dice);
            average = (dice + (sides * dice));
            average = average / 2;
            printf("The average value is %lf\n", average);
        } else {
            printf("These dice will not produce a range.\n");
        }
    } else {
        printf("These dice will not produce a range.\n");
    }
    return 0;
}