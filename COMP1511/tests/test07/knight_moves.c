// Zeal L (abc982210694@gmail.com)
// 2020-11-18 16:52:42
// Tenth week in COMP1511
// Zid:z5325156

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#define LEN 8

void set_board(char *board[LEN][LEN]);

int main(int argc, char *argv[]) {
    if (argc != 3) {
        return 0;
    }
    char *start = argv[1];
    char *end = argv[2];
    // i.e. a8 -> 0,7    b5 -> 1,4
    int star_row = start[0] - 97;
    int star_col = start[1] - 49;
    int end_row = end[0] - 96;
    int end_col = end[1] - 48;
    
    char *board[LEN][LEN] = {0}; 
    set_board(board);
    
    return 0;
}

void set_board(char *board[LEN][LEN]) {
    for (int row = 0; row < LEN; row++) {
        for (int col = 0; col < LEN; col++) {
            char index[3];
            index[0] = 'a' + col;
            index[1] = '8' - row; 
            index[2] = '\0'; 
            board[row][col] = index;
            printf("%s ", board[row][col]);
        }
        printf("\n");
    }
}