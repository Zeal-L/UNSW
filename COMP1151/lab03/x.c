// By Zeal L, September 2020  Third week in COMP1511
// Zid:z5325156
#include<stdio.h>

int main(void){
    int size;
    printf("Enter size: ");
    scanf("%d", &size);
    for (int i = 0; i < size; i++) {
        for (int j = 0; j < size; j++) {
            if (i == j || j+1 == size-i) {
                printf("*");
            } else {
                printf("-");
            }
        }
        printf("\n");
    }
    return 0;
}