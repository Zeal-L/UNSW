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
// Draw Line
void line_drawing(int canvas[N_ROWS][N_COLS], int start_row,int start_col,int end_row,int end_col); 
// Fill Rectangle
void rectangle_filling(int canvas[N_ROWS][N_COLS], int *start_r,int *start_c,int *end_r,int *end_c); 
// Changes the value beyond the boundary to the maximum or minimum of the border
void hold_boundary(int *start_r,int *start_c,int *end_r,int *end_c);
// Checking the location of the given command on the canvas
int check_location(int start_row,int start_col,int end_row,int end_col);
// If draw it from the bottom up then flip the start and end
void flipping (int *cur_r, int *cur_c, int *start_r,int *start_c,int *end_r,int *end_c);


int main(void) {
    int canvas[N_ROWS][N_COLS];
    clearCanvas(canvas);

    int command = 0, start_row = 0, start_col = 0, end_row = 0, end_col = 0;
    int *start_r = &start_row, *start_c = &start_col, *end_r= &end_row, *end_c = &end_col;
    
    while (scanf("%d%d%d%d%d", &command, &start_row, &start_col, &end_row, &end_col) == 5) {
        
        if (command == 1) { // Draw Line
            
            if (check_location(start_row, start_col, end_row, end_col) == 0) {

                line_drawing(canvas, start_row, start_col, end_row, end_col);

                displayCanvas(canvas);
                printf("\n");
                canvasGraph(canvas);
                printf("\n");
                
            } else if (check_location(start_row, start_col, end_row, end_col) == 1) {
                        
                hold_boundary(start_r, start_c, end_r, end_c);
                line_drawing(canvas, start_row, start_col, end_row, end_col);
                
                displayCanvas(canvas);
                printf("\n");
                canvasGraph(canvas);
                printf("\n");
            }
        } 
        if (command == 2) { // Fill Rectangle

            if (check_location(start_row, start_col, end_row, end_col) == 0) {

                rectangle_filling(canvas, start_r, start_c, end_r, end_c);
                
                displayCanvas(canvas);
                printf("\n");
                canvasGraph(canvas);
                printf("\n");

            } else if (check_location(start_row, start_col, end_row, end_col) == 1) {
                
                hold_boundary(start_r, start_c, end_r, end_c);
                rectangle_filling(canvas, start_r, start_c, end_r, end_c);

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

//If draw it from the bottom up then flip the start and end, otherwise do nothing
void flipping (int *cur_r, int *cur_c, int *start_r,int *start_c,int *end_r,int *end_c) {
    *cur_r = *start_r;
    *cur_c = *start_c;
    if (*start_r > *end_r) { 
        *cur_r = *end_r;
        *cur_c = *end_c;
        *end_r = *start_r;
        *end_c = *start_c;
        *start_r = *cur_r;
        *start_c = *cur_c;
    } 
}

//Draw Line
void line_drawing(int canvas[N_ROWS][N_COLS], int start_row,int start_col,int end_row,int end_col) { 

    int cur_row, cur_col;
    int *cur_r = &cur_row, *cur_c = &cur_col, 
    *start_r = &start_row, *start_c = &start_col, *end_r = &end_row, *end_c = &end_col;
    flipping (cur_r, cur_c, start_r, start_c, end_r, end_c);


    // Draw only perfectly horizontal or vertical lines
    if (start_row == end_row || start_col == end_col) {

         if (start_row <= end_row && start_col == end_col) { // from top to bottom
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
    } else if (start_row - end_row == start_col - end_col) { // Or 45° Diagonals ---- top-left to bottom-right 
        int counter = 0;
        while (counter <= end_row - start_row) {
            canvas[cur_row][cur_col] = BLACK;
            cur_row++;
            cur_col++;
            counter++;
        }

    } else if (start_row - end_row == -1 * (start_col - end_col)) { // Or 45° Diagonals ---- top-right to bottom-left
        int counter = 0;
        while (counter <= start_col - end_col) {
            canvas[cur_row][cur_col] = BLACK;
            cur_row++;
            cur_col--;
            counter++;
        }
    }
}

// Fill Rectangle
void rectangle_filling(int canvas[N_ROWS][N_COLS], int *start_r,int *start_c,int *end_r,int *end_c) {

    int cur_row, cur_col;
    int *cur_r = &cur_row, *cur_c = &cur_col;
    flipping (cur_r, cur_c, start_r, start_c, end_r, end_c);

    if (*start_r <= *end_r && *start_c <= *end_c) { // top-left to bottom-right
        while (cur_row <= *end_r) {
            cur_col = *start_c;
            while (cur_col <= *end_c) {
                canvas[cur_row][cur_col] = BLACK;
                cur_col++;
            }
            cur_row++;
        }
    } else if (*start_r <= *end_r && *start_c >= *end_c) { // top-right to bottom-left
        while (cur_row <= *end_r) {
            cur_col = *start_c;
            while (cur_col >= *end_c) {
                canvas[cur_row][cur_col] = BLACK;
                cur_col--;
            }
            cur_row++;
        }
    }
}

//Changes the value beyond the boundary to the maximum or minimum of the border
void hold_boundary(int *start_r,int *start_c,int *end_r,int *end_c) {

    int cur_row, cur_col;
    int *cur_r = &cur_row, *cur_c = &cur_col;
    flipping (cur_r, cur_c, start_r, start_c, end_r, end_c);

    // Boundary for Diagonals, Shorten both the protruding rows and columns
    int temp_start_row = *start_r, temp_start_col = *start_c, temp_end_row = *end_r, temp_end_col = *end_c;
    if (*start_r - *end_r == *start_c - *end_c) { // 45° Diagonals ---- top-left to bottom-right
        if (*end_r > N_ROWS-1) { // Lower right corner protruding
            while ((*end_r > N_ROWS-1) || (*end_c > N_COLS-1)) {
                temp_end_row--;
                temp_end_col--;
                *end_r = temp_end_row;
                *end_c = temp_end_col;
            }
        } else if (*start_r < 0) { // Top left corner protrusion
            while ((*start_r < 0) || (*start_c < 0)) {
                temp_start_row++;
                temp_start_col++;
                *start_r = temp_start_row;
                *start_c = temp_start_col;
            }
        }
    } else if (*start_r - *end_r == -1 * (*start_c - *end_c)) { // 45° Diagonals ---- top-right to bottom-left
        if (*end_r > N_ROWS-1) { // Lower left corner protruding
            while ((*end_r > N_ROWS-1) || (*end_c < 0)) {
                temp_end_row--;
                temp_end_col++;
                *end_r = temp_end_row;
                *end_c = temp_end_col;
            }
        } else if (*start_r < 0) { // Top right corner protruding
            while ((*start_r < 0) || (*start_c > N_COLS-1)) {
                temp_start_row++;
                temp_start_col--;
                *start_r = temp_start_row;
                *start_c = temp_start_col;
            }
        }
    }

    // Normal boundary
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
    if ((start_row >= 0 && start_row < N_ROWS) && 
        (start_col >= 0 && start_col < N_COLS) && 
          (end_row >= 0 && end_row < N_ROWS) &&
          (end_col >= 0 && end_col < N_COLS)) {
        return 0;
    }
    // if the given command is partially outside the canvas, only draw the section that is within the canvas
    if (((start_row >= 0 && start_row < N_ROWS) && (start_col >= 0 && start_col < N_COLS)) ||
            ((end_row >= 0 && end_row < N_ROWS) && (end_col >= 0 && end_col < N_COLS))) {
        return 1;
    }     
    return -1;       
}