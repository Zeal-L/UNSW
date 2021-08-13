// COMP1521 20T3 final exam Q7 C reference

#include <stdio.h>

void read_array(int rows, int cols, int a[rows][cols]);
void reflect(int rows, int cols, int a[rows][cols], int b[cols][rows]);
void print_array(int rows, int cols, int a[rows][cols]);

int main(void) {
    int rows;
    int cols;
    scanf("%d", &rows);
    scanf("%d", &cols);
    int array1[rows][cols];
    int array2[cols][rows];
    read_array(rows, cols, array1);
    reflect(rows, cols, array1, array2);
    print_array(rows, cols, array1);
	printf("\n");
    print_array(cols, rows, array2);
}


void read_array(int rows, int cols, int a[rows][cols]) {
    for (int r = 0; r < rows; r++) {
        for (int c = 0; c < cols; c++) {
            scanf("%d", &a[r][c]);
        }
    }
}


void reflect(int rows, int cols, int a[rows][cols], int b[cols][rows]) {
    for (int r = 0; r < rows; r++) {
        for (int c = 0; c < cols; c++) {
            b[c][r] = a[r][c];
        }
    }
}


void print_array(int rows, int cols, int a[rows][cols]) {
    for (int r = 0; r < rows; r++) {
        for (int c = 0; c < cols; c++) {
            printf("%d ", a[r][c]);
        }
        printf("\n");
    }
}
