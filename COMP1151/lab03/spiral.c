// Zeal L (abc982210694@gmail.com), September 2020  
// Third week in COMP1511
// Zid:z5325156
#include<stdio.h>

int main(void){
    int size;
    printf("Enter size: ");
    scanf("%d", &size);
    for (int line = 1; line <= size; line++) {
        int length = 1;
        for (int row = 1; row <= size; row++) {
            if ((row == 2 * length - 1 && line != 2 * length && line < size - 2 * length + 1) || (row == size - line && line % 2 == 0 && row < size - 2 * length ) || (row > size - 2 * length && row % 2 == 1 && row != line - 1)) {
                printf("*");
                length += 1;
            } else if ((line % 2 == 1 && row >= line - 1 && row <= size - line + 1) || ((line > size / 2 + 1) && (line % 2 == 1 && row <= line && row >= size - line + 1))) {
                printf("*");
            } else {
                printf("-");
            }
        }
        printf("\n");
    }
    return 0;
}