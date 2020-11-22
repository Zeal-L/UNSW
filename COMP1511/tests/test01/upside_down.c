// Zeal L (abc982210694@gmail.com), September 2020  
// Third week in COMP1511
// Zid:z5325156
#include<stdio.h>

int main(void){
    double a, b, c;
    printf("Please enter three numbers: ");
    scanf("%lf %lf %lf", &a, &b, &c);
    if (a < b && b < c) {
        printf("up\n");
    } else if (a > b && b > c) {
        printf("down\n");
    } else printf("neither\n");
    return 0;
}