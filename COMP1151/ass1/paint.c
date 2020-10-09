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
#define DARK  1  
#define GREY  2
#define LIGHT 3
#define WHITE 4

// Display the canvas graph.
void canvasGraph(int canvas[N_ROWS][N_COLS]);
// Display the canvas.
void displayCanvas(int canvas[N_ROWS][N_COLS]);
// Clear the canvas by setting every pixel to be white.
void clearCanvas(int canvas[N_ROWS][N_COLS]);
//Draw Line
void line_drawing(int canvas[N_ROWS][N_COLS], int start_row,int start_col,int end_row,int end_col); 
//Draw Diagonals
void diagonals(int canvas[N_ROWS][N_COLS], int start_row,int start_col,int end_row,int end_co);
//Fill Rectangle
void rectangle_filling(int canvas[N_ROWS][N_COLS], int start_row,int start_col,int end_row,int end_col); 
//Changes the value beyond the boundary to the maximum or minimum of the border
void hold_boundary(int *start_r,int *start_c,int *end_r,int *end_c);
// Checking the location of the given command on the canvas
int check_location(int start_row,int start_col,int end_row,int end_col);


int main(void) {
    int canvas[N_ROWS][N_COLS];
    clearCanvas(canvas);

    int command = 0, start_row = 0, start_col = 0, end_row = 0, end_col = 0;
    int *start_r = &start_row, *start_c = &start_col, *end_r= &end_row, *end_c = &end_col;
    
    while (scanf("%d%d%d%d%d", &command, &start_row, &start_col, &end_row, &end_col) == 5) {
        
        if (command == 1) { // Draw Line
            
            if (check_location(start_row, start_col, end_row, end_col) == 0) {

                // Draw only perfectly horizontal or vertical lines
                if (start_row == end_row || start_col == end_col) {

                    line_drawing(canvas, start_row, start_col, end_row, end_col);

                    displayCanvas(canvas);
                    printf("\n");
                    canvasGraph(canvas);
                    printf("\n");
                }

            } else if (check_location(start_row, start_col, end_row, end_col) == 1) {
                        
                        hold_boundary(start_r, start_c, end_r, end_c);
                        line_drawing (canvas, start_row, start_col, end_row, end_col);
                        
                        displayCanvas(canvas);
                        printf("\n");
                        canvasGraph(canvas);
                        printf("\n");
            }
        } 
        if (command == 2) { // Fill Rectangle

            if (check_location(start_row, start_col, end_row, end_col) == 0) {

                rectangle_filling(canvas, start_row, start_col, end_row, end_col);
                
                displayCanvas(canvas);
                printf("\n");
                canvasGraph(canvas);
                printf("\n");

            } else if (check_location(start_row, start_col, end_row, end_col) == 1) {
                
                hold_boundary(start_r, start_c, end_r, end_c);
                rectangle_filling(canvas, start_row, start_col, end_row, end_col);

                displayCanvas(canvas);
                printf("\n");
                canvasGraph(canvas);
                printf("\n");
            }
        }
        if (command == 3) { // Add Shade


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
            if (canvas[row][col] == BLACK) {
                printf("  ");
            } else if (canvas[row][col] == DARK) {
                printf("░░");
            } else if (canvas[row][col] == GREY) {
                printf("▒▒");
            } else if (canvas[row][col] == LIGHT) {
                printf("▓▓");
            } else if (canvas[row][col] == WHITE) {
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
void line_drawing(int canvas[N_ROWS][N_COLS], int start_row,int start_col,int end_row,int end_col) { 
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

//Draw Diagonals
void diagonals(int canvas[N_ROWS][N_COLS], int start_row,int start_col,int end_row,int end_co) {
    int cur_row = start_row;
    int cur_col = start_col;

}

//Fill Rectangle
void rectangle_filling(int canvas[N_ROWS][N_COLS], int start_row,int start_col,int end_row,int end_col) {
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

//Changes the value beyond the boundary to the maximum or minimum of the border
void hold_boundary(int *start_r,int *start_c,int *end_r,int *end_c) {

    if (*start_r < 0)          *start_r = 0;
    if (*start_r > N_ROWS)     *start_r = N_ROWS-1;
    if (*start_c < 0)          *start_c = 0;
    if (*start_c > N_COLS)     *start_c = N_COLS-1;
    if (*end_r > N_ROWS)       *end_r = N_ROWS-1;
    if (*end_r < 0)            *end_r = 0;
    if (*end_c > N_COLS)       *end_c = N_COLS-1;
    if (*end_c < 0)            *end_c = 0;
}

// Checking the location of the given command on the canvas
int check_location(int start_row, int start_col, int end_row, int end_col) {
    
    // if the given command both starts and ends outside the canvas, ignore it
    if ((start_row > 0 && start_row < N_ROWS) && 
        (start_col > 0 && start_col < N_COLS) && 
          (end_row > 0 && end_row < N_ROWS) &&
          (end_col > 0 && end_col < N_COLS)) {
        return 0;
    }
    // if the given command is partially outside the canvas, only draw the section that is within the canvas
    if (((start_row > 0 && start_row < N_ROWS) && (start_col > 0 && start_col < N_COLS)) ||
                   ((end_row > 0 && end_row < N_ROWS) && (end_col > 0 && end_col < N_COLS))) {
        return 1;
    }       
    return -1;       
}