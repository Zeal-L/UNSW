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
void line_drawing(int canvas[N_ROWS][N_COLS], int start_row,int start_col,int end_row,int end_col, int new_shade, int command); 
// Fill Rectangle
void rectangle_filling(int canvas[N_ROWS][N_COLS], int *start_r,int *start_c,int *end_r,int *end_c, int new_shade, int command); 
// Changes the value beyond the boundary to the maximum or minimum of the border
void hold_boundary(int *start_r,int *start_c,int *end_r,int *end_c, int command);
// Checking the location of the given command on the canvas
int check_location(int start_row,int start_col,int end_row,int end_col);
// If draw it from the bottom up then flip the start and end
void flipping (int *start_r,int *start_c,int *end_r,int *end_c);
// Copy and Paste
void copy_paste (int canvas[N_ROWS][N_COLS], int start_row, int start_col, int end_row, int end_col, int target_row, int target_col);
// Macro Playback
void macro_play(int canvas[N_ROWS][N_COLS], int macro_store[10][5], int row_offset, int col_offset, int num_commands, int new_shade);



int main(void) {
    int canvas[N_ROWS][N_COLS], macro_store[10][5];
    clearCanvas(canvas);

    int command, start_row, start_col, end_row, end_col, new_shade = 0, num_commands = 0;;
    int *start_r = &start_row, *start_c = &start_col, *end_r= &end_row, *end_c = &end_col;
    
    while (scanf("%d", &command) == 1) {

        if (command == 1) { // Draw Line
            while (scanf("%d%d%d%d", &start_row, &start_col, &end_row, &end_col) == 4) {
                line_drawing(canvas, start_row, start_col, end_row, end_col, new_shade, command);
                break;
            }
        } 
        if (command == 2) { // Fill Rectangle
            while (scanf("%d%d%d%d", &start_row, &start_col, &end_row, &end_col) == 4) {
                rectangle_filling(canvas, start_r, start_c, end_r, end_c, new_shade, command);
                break;
            }
            
        }
        if (command == 3) { // Change Shade
            int check_shade = 0;
            while (scanf("%d", &check_shade) == 1) {
                if (check_shade >= 0 && check_shade <= 4) new_shade = check_shade;
                break;
            }
        } 
        if (command == 4) { // Copy and Paste
            int target_row, target_col;
            while (scanf("%d%d%d%d%d%d", &start_row, &start_col, &end_row, &end_col, &target_row, &target_col) == 6) {
                copy_paste (canvas, start_row, start_col, end_row, end_col, target_row, target_col);

                displayCanvas(canvas);
                printf("\n");
                canvasGraph(canvas);
                printf("\n");

                break;
            }
        }
        if (command == 5) { // Macro Record
            while (scanf("%d", &num_commands) == 1) {
                for (int i = 0; i < num_commands; i++) {
                    for (int j = 0; j < 5; j++) {
                        scanf("%d", &macro_store[i][j]);
                    }
                }
                break;
            }
        }
        if (command == 6) { // Macro Playback
            int row_offset = 0, col_offset = 0;
            while (scanf("%d%d", &row_offset, &col_offset) == 2) { 
                macro_play (canvas, macro_store, row_offset, col_offset, num_commands, new_shade);
                break;
            }
        }
    }
    return 0;
}

// Macro Playback
void macro_play(int canvas[N_ROWS][N_COLS], int macro_store[10][5], int row_offset, int col_offset, int num_commands, int new_shade) {
    if (num_commands != 0) { // Check if command 5 has been used
        for (int i = 0; i < num_commands; i++) {
            macro_store[i][1] += row_offset;
            macro_store[i][2] += col_offset;
            macro_store[i][3] += row_offset;
            macro_store[i][4] += col_offset;
            if (macro_store[i][0] == 1) { // Draw Line
                line_drawing(canvas, macro_store[i][1], macro_store[i][2], macro_store[i][3], macro_store[i][4], new_shade, macro_store[i][0]);
            } else if (macro_store[i][0] == 2) { // Fill Rectangle
                rectangle_filling(canvas, &macro_store[i][1], &macro_store[i][2], &macro_store[i][3], &macro_store[i][4], new_shade, macro_store[i][0]);
            }
        }
    }
}



// Copy and Paste
void copy_paste (int canvas[N_ROWS][N_COLS], int start_row, int start_col, int end_row, int end_col, int target_row, int target_col) {

    int cur_row = end_row - start_row + 1, cur_col = end_col - start_col + 1;
    int copy[cur_row][cur_col];
    
    for (int i = 0; i < cur_row; i++) {
        for (int j = 0; j < cur_col; j++) {
            copy[i][j] = canvas[start_row+i][start_col+j];
        }
    }
    for (int i = 0; i < cur_row; i++) {
        for (int j = 0; j < cur_col; j++) {
            // If paste partially outside the canvas, ignore it
            if ((target_row+i > N_ROWS-1) || (target_col+j > N_COLS-1) || (target_row+i < 0) || (start_col+j < 0)) break;
            canvas[target_row+i][target_col+j] = copy[i][j];
        }
    }
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
void line_drawing(int canvas[N_ROWS][N_COLS], int start_row,int start_col,int end_row,int end_col, int new_shade, int command) { 

    int *start_r = &start_row, *start_c = &start_col, *end_r = &end_row, *end_c = &end_col;
    // if the given command both starts and ends outside the canvas, ignore it
    if (check_location(start_row, start_col, end_row, end_col) == -1) return;
    hold_boundary(start_r, start_c, end_r, end_c, command);
    int cur_row = *start_r, cur_col = *start_c;

    // Draw only perfectly horizontal or vertical lines
    if (start_row == end_row || start_col == end_col) {

         if (start_row <= end_row && start_col == end_col) { // from top to bottom
            while (cur_row <= end_row) {
                canvas[cur_row][cur_col] = new_shade;
                cur_row++;
            }
        } else if (start_col <= end_col && start_row == end_row) { // from left to right
            while (cur_col <= end_col) {
                canvas[cur_row][cur_col] = new_shade;
                cur_col++;
            }
        } else if (start_col >= end_col && start_row == end_row) { // from right to left
            while (cur_col >= end_col) {
                canvas[cur_row][cur_col] = new_shade;
                cur_col--;
            }
            
        } 
    } else if (start_row - end_row == start_col - end_col) { // Or 45° Diagonals ---- top-left to bottom-right 
        int counter = 0;
        while (counter <= end_row - start_row) {
            canvas[cur_row][cur_col] = new_shade;
            cur_row++;
            cur_col++;
            counter++;
        }

    } else if (start_row - end_row == -1 * (start_col - end_col)) { // Or 45° Diagonals ---- top-right to bottom-left
        int counter = 0;
        while (counter <= start_col - end_col) {
            canvas[cur_row][cur_col] = new_shade;
            cur_row++;
            cur_col--;
            counter++;
        }
    }
    displayCanvas(canvas);
    printf("\n");
    canvasGraph(canvas);
    printf("\n");
}

// Fill Rectangle
void rectangle_filling(int canvas[N_ROWS][N_COLS], int *start_r,int *start_c,int *end_r,int *end_c, int new_shade, int command) {

    int start_row = *start_r, start_col = *start_c, end_row = *end_r, end_col = *end_c;
    // if the given command both starts and ends outside the canvas, ignore it
    if (check_location(start_row, start_col, end_row, end_col) == -1) return;
    hold_boundary(start_r, start_c, end_r, end_c, command);
    int cur_row = *start_r, cur_col = *start_c;

    if (*start_r <= *end_r && *start_c <= *end_c) { // top-left to bottom-right
        while (cur_row <= *end_r) {
            cur_col = *start_c;
            while (cur_col <= *end_c) {
                canvas[cur_row][cur_col] = new_shade;
                cur_col++;
            }
            cur_row++;
        }
    } else if (*start_r <= *end_r && *start_c >= *end_c) { // top-right to bottom-left
        while (cur_row <= *end_r) {
            cur_col = *start_c;
            while (cur_col >= *end_c) {
                canvas[cur_row][cur_col] = new_shade;
                cur_col--;
            }
            cur_row++;
        }
    }
    displayCanvas(canvas);
    printf("\n");
    canvasGraph(canvas);
    printf("\n");
}

//If draw it from the bottom up then flip the start and end, otherwise do nothing
void flipping (int *start_r,int *start_c,int *end_r,int *end_c) {
    int cur_r = *start_r;
    int cur_c = *start_c;
    if (*start_r > *end_r) { 
        cur_r = *end_r;
        cur_c = *end_c;
        *end_r = *start_r;
        *end_c = *start_c;
        *start_r = cur_r;
        *start_c = cur_c;
    } 
}

//Changes the value beyond the boundary to the maximum or minimum of the border
void hold_boundary(int *start_r,int *start_c,int *end_r,int *end_c, int command) {

    flipping (start_r, start_c, end_r, end_c);

    // Checking if it is 45° Diagonals
    if ((*start_r - *end_r == *start_c - *end_c) || (*start_r - *end_r == -1 * (*start_c - *end_c))) {
        // Boundary for Diagonals, Shorten both the protruding rows and columns
        int temp_start_row = *start_r, temp_start_col = *start_c, temp_end_row = *end_r, temp_end_col = *end_c;
        if ((*start_r - *end_r == *start_c - *end_c) && (command == 1)) { // 45° Diagonals ---- top-left to bottom-right
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
    } else if ((*start_r == *end_r || *start_c == *end_c) || (command == 2)) {
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
}

// Checking the location of the given command on the canvas
int check_location(int start_row, int start_col, int end_row, int end_col) {
    
    // if the given command both starts and ends outside the canvas, ignore it, return -1
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