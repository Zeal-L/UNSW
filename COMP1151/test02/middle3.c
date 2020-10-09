// Zeal L (abc982210694@gmail.com), October 2020  
// Fourth week in COMP1511
// Zid:z5325156
#include<stdio.h>

int main(void){
    int a = 0, b = 0, c = 0;
    printf("Enter integer: ");
    scanf("%d", &a);
    printf("Enter integer: ");
    scanf("%d", &b);
    printf("Enter integer: ");
    scanf("%d", &c);
    if (a == b) {
        printf("Middle: %d\n", a);
    } else if (b == c) {
        printf("Middle: %d\n", b);
    } else if (c == a) {
        printf("Middle: %d\n", c);
    } else {
        printf("Middle: %d\n", a * ((a<b && a>c) || (a>b && a<c)) + 
                            b * ((b<a && b>c) || (b>a && b<c)) + 
                            c * ((c<a && c>b) || (c>a && c<b)));
    }
    return 0;
}