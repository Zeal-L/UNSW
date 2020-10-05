// Assignment 1 20T3 COMP1511: CS Paint
// paint.c
//
// This program was written by Zeal Liang (z5325156)
// on 4/10/2020
//
// Version 1.0.0 (2020-10-04): Assignment released.

#include <stdio.h>

// The dimensions of the canvas (20 rows x 36 columns).
#define N_ROWS 20
#define N_COLS 36

// Shades (assuming your terminal has a black background).
#define BLACK 0
#define Dark  1  
#define Grey  2
#define Light 3
#define WHITE 4


// Display the canvas graph.
void canvasGraph(int canvas[N_ROWS][N_COLS]);
// Display the canvas.
void displayCanvas(int canvas[N_ROWS][N_COLS]);
// Clear the canvas by setting every pixel to be white.
void clearCanvas(int canvas[N_ROWS][N_COLS]);
//Draw Line
void line_drawing (int canvas[N_ROWS][N_COLS], int start_row,int start_col,int end_row,int end_col); 
//Fill Rectangle
void rectangle_filling (int canvas[N_ROWS][N_COLS], int start_row,int start_col,int end_row,int end_col); 


int main(void) {
    int canvas[N_ROWS][N_COLS];
    clearCanvas(canvas);
    while (1) {
            
        int command = 0, start_row = 0, start_col = 0, end_row = 0, end_col = 0;
        scanf("%d%d%d%d%d", &command, &start_row, &start_col, &end_row, &end_col);
        
        if (command == 1) { // command 1 means Draw Line
            //if the given command both starts and ends outside the canvas, ignore it
            if ((start_row > 0 && start_row < N_ROWS) && 
                (start_col > 0 && start_col < N_COLS) && 
                  (end_row > 0 && end_row < N_ROWS) &&
                  (end_col > 0 && end_col < N_COLS)) {
                //if the given command would not give an entirely horizontal or vertical line, ignore it
                if (start_row == end_row || start_col == end_col) {
                    line_drawing (canvas, start_row, start_col, end_row, end_col);
                    displayCanvas(canvas);
                    printf("\n");
                    canvasGraph(canvas);
                    printf("\n");
                }
            //if the given command is partially outside the canvas, only draw the section that is within the canvas
            } else if (((start_row > 0 && start_row < N_ROWS) && (start_col > 0 && start_col < N_COLS)) ||
                           ((end_row > 0 && end_row < N_ROWS) && (end_col > 0 && end_col < N_COLS))) {
                        //Changes the value beyond the boundary to the maximum or minimum of the border
                        if (start_row < 0) start_row = 0;
                        if (start_col < 0) start_col = 0;
                        if (end_row > N_ROWS) end_row = N_ROWS;
                        if (end_col > N_COLS) end_col = N_COLS;
                        line_drawing (canvas, start_row, start_col, end_row, end_col);
                        displayCanvas(canvas);
                        printf("\n");
                        canvasGraph(canvas);
                        printf("\n");
            }

        } else if (command == 2) {

            //if the given command both starts and ends outside the canvas, ignore it
            if ((start_row > 0 && start_row < N_ROWS) && 
                (start_col > 0 && start_col < N_COLS) && 
                  (end_row > 0 && end_row < N_ROWS) &&
                  (end_col > 0 && end_col < N_COLS)) {

                rectangle_filling(canvas, start_row, start_col, end_row, end_col);
                displayCanvas(canvas);
                printf("\n");
                canvasGraph(canvas);
                printf("\n");
            //if the given command is partially outside the canvas, only draw the section that is within the canvas
            } else if (((start_row > 0 && start_row < N_ROWS) && (start_col > 0 && start_col < N_COLS)) ||
                           ((end_row > 0 && end_row < N_ROWS) && (end_col > 0 && end_col < N_COLS))) {
                //Changes the value beyond the boundary to the maximum or minimum of the border
                if (start_row < 0) start_row = 0;
                if (start_col < 0) start_col = 0;
                if (end_row > N_ROWS) end_row = N_ROWS;
                if (end_col > N_COLS) end_col = N_COLS;

                rectangle_filling(canvas, start_row, start_col, end_row, end_col);
                displayCanvas(canvas);
                printf("\n");
                canvasGraph(canvas);
                printf("\n");
            }
        }
    }
    return 0;
}
    


// Display the canvas graph.
void canvasGraph(int canvas[N_ROWS][N_COLS]) {
    int row = 0;
    while (row < N_ROWS) {
        int col = 0;
        while (col < N_COLS) {
            if (canvas[row][col] == 0) {
                printf("  ");
            } else if (canvas[row][col] == 1) {
                printf("░░");
            } else if (canvas[row][col] == 2) {
                printf("▒▒");
            } else if (canvas[row][col] == 3) {
                printf("▓▓");
            } else if (canvas[row][col] == 4) {
                printf("▇▇");
            }
            col++;
        }
        row++;
        printf("\n");
    }
}

// Displays the canvas, by printing the integer value stored in
// each element of the 2-dimensional canvas array.
//
// You should not need to change the displayCanvas function.
void displayCanvas(int canvas[N_ROWS][N_COLS]) {
    int row = 0;
    while (row < N_ROWS) {
        int col = 0;
        while (col < N_COLS) {
            printf("%d ", canvas[row][col]);
            col++;
        }
        row++;
        printf("\n");
    }
}

// Sets the entire canvas to be blank, by setting each element in the
// 2-dimensional canvas array to be WHITE (which is #defined at the top
// of the file).
//
// You should not need to change the clearCanvas function.
void clearCanvas(int canvas[N_ROWS][N_COLS]) {
    int row = 0;
    while (row < N_ROWS) {
        int col = 0;
        while (col < N_COLS) {
            canvas[row][col] = WHITE;
            col++;
        }
        row++;
    }
}

//Draw Line
void line_drawing (int canvas[N_ROWS][N_COLS], int start_row,int start_col,int end_row,int end_col) { 
    int cur_row = start_row;
    int cur_col = start_col;
    if (start_row >= end_row && start_col == end_col) { // up
        while (cur_row >= end_row) {
            canvas[cur_row][cur_col] = BLACK;
            cur_row--;
        }
    } else if (start_row <= end_row && start_col == end_col) { // down
        while (cur_row <= end_row) {
            canvas[cur_row][cur_col] = BLACK;
            cur_row++;
        }
    } else if (start_col <= end_col && start_row == end_row) { // from left to right
        while (cur_col <= end_col) {
            canvas[cur_row][cur_col] = BLACK;
            cur_col++;
        }
    } else if (start_col >= end_col && start_row == end_row) { // from right to left
        while (cur_col >= end_col) {
            canvas[cur_row][cur_col] = BLACK;
            cur_col--;
        }
    }
}

//Fill Rectangle
void rectangle_filling (int canvas[N_ROWS][N_COLS], int start_row,int start_col,int end_row,int end_col) {
    int cur_row = start_row;
    int cur_col = start_col;
    if (start_row > end_row) { //If draw it from the bottom up then flip the row
        cur_row = end_row;
        end_row = start_row;
    } 
    if (start_row <= end_row && start_col <= end_col) { // top-left to bottom-right
        while (cur_row <= end_row) {
            cur_col = start_col;
            while (cur_col <= end_col) {
                canvas[cur_row][cur_col] = BLACK;
                cur_col++;
            }
            cur_row++;
        }
    } else if (start_row <= end_row && start_col >= end_col) { // top-right to bottom-left
       while (cur_row <= end_row) {
           cur_col = start_col;
            while (cur_col >= end_col) {
                canvas[cur_row][cur_col] = BLACK;
                cur_col--;
            }
            cur_row++;
        }
    }
}