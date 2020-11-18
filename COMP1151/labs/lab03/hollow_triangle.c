// By Zeal L, September 2020  Third week in COMP1511
// Zid:z5325156
#include<stdio.h>

int main(void){
    int size;
    printf("Enter size: ");
    scanf("%d", &size);
    for (int row = 0; row < size; row++) {
        for (int col = 0; col < size; col++) {
            if (col == row || row+1 == size || col == 0) {
                printf("*");
            } else {
                printf(" ");
            }
        }
        printf("\n");
    }
    return 0;
}