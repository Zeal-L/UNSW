// Zeal L (abc982210694@gmail.com), October 2020  
// Fourth week in COMP1511
// Zid:z5325156
#include<stdio.h>

int main(void){
    int size = 0;
    printf("Enter square size: ");
    scanf("%d", &size);
    
    int row = size-1;
    int col = size-1;
    int temp_col = 0;
    int temp_row = 0;

    for (int i = 0; i < size; i++) {
        for (int j = 0; j < size; j++) {
            if (j < size*0.5) {
                if (col < 10) {
                    printf(" %d ", col);
                } else {
                    printf("%d ", col);
                }
                col--;
                temp_col = col + 1;
            } else if (j > size*0.5) {
                temp_col++;
                if (temp_col < 10) {
                    printf(" %d ", temp_col);
                } else {
                    printf("%d ", temp_col);
                }
            } 
        }
        printf("\n");
        if (i+1 < size*0.5) {
            row--;
            temp_row = row + 1;
            col = row;
        } else if (i > size*0.5-1) {
            col = temp_row;
            temp_row++;
        } 
    }
    return 0;
}
