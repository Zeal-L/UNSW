// Zeal L (abc982210694@gmail.com)
// 2020-10-20 07:59:35
// Sixth week in COMP1511
// Zid:z5325156
//
// identity_matrix.c
// Given a 2D array (or matrix), find the 
// Corresponding identity matrix
#include <stdio.h>
#include <stdlib.h>


void make_identity(int size, int matrix[size][size]);
void print_matrix(int size, int matrix[size][size]);

// This is a simple main function that you can use to test your identity_matrix
// function.
// It will not be marked - only your array_sum_prod function will be marked.
//
// Note: the autotest does not call this main function!
// It calls your identity_matrix function directly.
// Any changes that you make to this main function will 
// not affect the autotests.
int main(void){

    int array3[3][3] = {{0, 1, 2}, {3, 4, 5}, {6, 7, 8}};

    make_identity(3, array3);

    print_matrix(3, array3);

    return 0;
}

//Makes a square matrix into an identity matrix
void make_identity(int size, int matrix[size][size]) {
    //TODO: Complete this function
    for (int i = 0; i < size; i++) {
        for (int j = 0; j < size; j++) {
            if (i == j) {
                matrix[i][j] = 1;
            } else {
                matrix[i][j] = 0;
            } 
        }
    }

}

//Prints out a square matrix of any size
void print_matrix(int size, int matrix[size][size]) {
    int i = 0;
    while (i < size){
        int j = 0;
        while (j < size){
            printf("%d ", matrix[i][j]);
            j++;
        }
        printf("\n");
        i++;
    }

}


