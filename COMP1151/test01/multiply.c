// Zeal L (abc982210694@gmail.com), September 2020  
// Third week in COMP1511
// Zid:z5325156
#include<stdio.h>

int main(void){
    int a, b;
    scanf("%d %d", &a, &b);
    if (a < 0) a = a * -1;
    if (b < 0) b = b * -1;
    if (a == 0 || b == 0) {
        printf("zero\n");
    } else {
        printf("%d\n", a * b);
    }
    return 0;
}