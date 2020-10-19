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

// Display the canvas.
void displayCanvas(int canvas[N_ROWS][N_COLS]);
// Clear the canvas by setting every pixel to be white.
void clearCanvas(int canvas[N_ROWS][N_COLS]);

// Sets all canvas to be blank
void clearCanvasStore(int canvas_store[5][N_ROWS][N_COLS]);
// Save the current canvas state in canvas store
int saveCanvas(int canvas[N_ROWS][N_COLS], int canvas_s[5][N_ROWS][N_COLS], int canvas_n);
// Displays the saved canvas
void displayCanvasStore(int canvas_store[5][N_ROWS][N_COLS], int canvas_n);

// Draw Line
void lineDrawing(int canvas[N_ROWS][N_COLS], int start_row, int start_col, int end_row, int end_col, int shade); 
// Fill Rectangle
void rectangleFilling(int canvas[N_ROWS][N_COLS], int *start_r, int *start_c, int *end_r, int *end_c, int shade); 

// Checking the location of the given command on the canvas
int checkLocation(int start_row, int start_col, int end_row, int end_col);
// If draw it from the bottom up then flip the start and end
void flipping(int *start_r, int *start_c,int *end_r, int *end_c);

// Changes the value beyond the boundary to the maximum or minimum of the border
void holdBoundary(int *start_r, int *start_c, int *end_r, int *end_c);
// Diagonals' Boundary, Shorten both the protruding rows and columns
void diagonalBoundary(int *start_r, int *start_c, int *end_r, int *end_c);

// Copy and Paste
void copyPaste (int canvas[N_ROWS][N_COLS]);
// Macro Record
int macroRecord (int macro_store[10][5], int num_com);
// Macro Playback
void macroPlay(int canvas[N_ROWS][N_COLS], int macro_s[10][5], int row_o, int col_o, int num_com, int shade);


int main(void) {
    int canvas[N_ROWS][N_COLS], macro_store[10][5], canvas_store[5][N_ROWS][N_COLS];
    int canvas_number = 0;
    clearCanvas(canvas);
    // Sets all canvas to be blank
    clearCanvasStore(canvas_store);
    int command, start_row, start_col, end_row, end_col, shade = 0, num_commands = 0;
    int *start_r = &start_row, *start_c = &start_col, *end_r= &end_row, *end_c = &end_col;
    
    while (scanf("%d", &command) == 1) {
        if (command == 1) { // Draw Line
            if (scanf("%d %d %d %d", &start_row, &start_col, &end_row, &end_col) == 4) {
                lineDrawing (canvas, start_row, start_col, end_row, end_col, shade);
            }

        } else if (command == 2) { // Fill Rectangle
            if (scanf("%d %d %d %d", &start_row, &start_col, &end_row, &end_col) == 4) {
                rectangleFilling (canvas, start_r, start_c, end_r, end_c, shade);
            }

        } else if (command == 3) { // Change Shade
            int check_shade = 0;
            if (scanf("%d", &check_shade) == 1) {
                if (check_shade >= 0 && check_shade <= 4) shade = check_shade;
            }

        } else if (command == 4) { // Copy and Paste
            copyPaste(canvas);

        } else if (command == 5) { // Macro Record
            num_commands = macroRecord(macro_store, num_commands);

        } else if (command == 6) { // Macro Playback
            int row_offset, col_offset;
            if (scanf("%d %d", &row_offset, &col_offset) == 2) { 
                macroPlay (
                    canvas, macro_store, row_offset, 
                    col_offset, num_commands, shade
                );            
            }

        } else if (command == 7) { // Save state
            canvas_number = saveCanvas(canvas, canvas_store, canvas_number);
        }
    }
    displayCanvasStore(canvas_store, canvas_number);
    displayCanvas(canvas);
    printf("\n");
    canvasGraph(canvas);
    printf("\n");
    return 0;
}

// Save the current canvas state in canvas store
int saveCanvas(int canvas[N_ROWS][N_COLS], int canvas_s[5][N_ROWS][N_COLS], int canvas_n) {
    for (int i = 1; i < 5 && canvas_n > 4; i++) {
        for (int row = 0; row < N_ROWS; row++) {
            for (int col = 0; col < N_COLS; col++) {
                canvas_s[i-1][row][col] = canvas_s[i][row][col];
            }
        }
    }
    if (canvas_n > 4) canvas_n = 4;
    for (int row = 0; row < N_ROWS; row++) {
        for (int col = 0; col < N_COLS; col++) {
            canvas_s[canvas_n][row][col] = canvas[row][col];
        }
    }
    canvas_n++;
    return canvas_n;
}

// Displays the saved canvas
void displayCanvasStore(int canvas_store[5][N_ROWS][N_COLS], int canvas_n) {
    for (int i = 0; i < canvas_n; i++) {
        for (int row = 0; row < N_ROWS; row++) {
            for (int col = 0; col < N_COLS; col++) {
                printf("%d ", canvas_store[i][row][col]);
            }
            printf("\n");
        }
        printf("\n");
    }
}

// Sets all canvas to be blank
void clearCanvasStore(int canvas_store[5][N_ROWS][N_COLS]) {
    for (int i = 0; i < 5; i++) {
        for (int row = 0; row < N_ROWS; row++) {
            for (int col = 0; col < N_COLS; col++) {
                canvas_store[i][row][col] = WHITE;
            }
        }
    }
}

// Macro Record
int macroRecord (int macro_store[10][5], int num_com) {
    if (scanf("%d", &num_com) == 1) {
        for (int i = 0; i < num_com; i++) {
            for (int j = 0; j < 5; j++) {
                scanf("%d", &macro_store[i][j]);
            }
        }
    }
    return num_com;
}

// Macro Playback
void macroPlay(int canvas[N_ROWS][N_COLS], int macro_s[10][5], int row_o, int col_o, int num_com, int shade) {
    if (num_com != 0) { // Check if command 5 has been used
        for (int i = 0; i < num_com; i++) {
            macro_s[i][1] += row_o;
            macro_s[i][2] += col_o;
            macro_s[i][3] += row_o;
            macro_s[i][4] += col_o;
            if (macro_s[i][0] == 1) { // Draw Line
                lineDrawing (
                    canvas, macro_s[i][1], macro_s[i][2],
                    macro_s[i][3], macro_s[i][4], shade
                );
            } else if (macro_s[i][0] == 2) { // Fill Rectangle
                rectangleFilling (
                    canvas, &macro_s[i][1], &macro_s[i][2], 
                    &macro_s[i][3], &macro_s[i][4], shade
                );
            }
        }
    }
}

// Copy and Paste
void copyPaste (int canvas[N_ROWS][N_COLS]) {
    int start_row, start_col, end_row, end_col, target_row, target_col;
    if (scanf("%d %d %d %d %d %d", 
        &start_row, &start_col, &end_row, &end_col, &target_row, &target_col) == 6) {

        int cur_row = end_row - start_row + 1, cur_col = end_col - start_col + 1;
        int copy[cur_row][cur_col];
        for (int i = 0; i < cur_row; i++) {
            for (int j = 0; j < cur_col; j++) {
                copy[i][j] = canvas[start_row+i][start_col+j];
            }
        }

        int check = 0;
        for (int i = 0; i < cur_row; i++) {
            check = 0;
            for (int j = 0; j < cur_col && check == 0; j++) {
                // If paste partially outside the canvas, ignore it
                if ((target_row + i > N_ROWS-1))        check = 1;
                else if (target_col + j > N_COLS-1)     check = 1;
                else if (target_row + i < 0)            check = 1;
                else if (start_col + j < 0)             check = 1;
                else canvas[target_row+i][target_col+j] = copy[i][j];
            }
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

// Draw Line
void lineDrawing(int canvas[N_ROWS][N_COLS], int start_row, int start_col, int end_row, int end_col, int shade) { 

    int *start_r = &start_row, *start_c = &start_col;
    int *end_r = &end_row, *end_c = &end_col;
    // if the given command both starts and ends outside the canvas, ignore it
    if (checkLocation(start_row, start_col, end_row, end_col) == -1) return;
    int cur_row = *start_r, cur_col = *start_c;

    // Checking if it is 45° Diagonals
    if (start_row - end_row == start_col - end_col) {
        diagonalBoundary(start_r, start_c, end_r, end_c);
        cur_row = *start_r, cur_col = *start_c;
        int counter = 0; // top-left to bottom-right
        while (counter <= end_row - start_row) {
            canvas[cur_row][cur_col] = shade;
            cur_row++;
            cur_col++;
            counter++;
        }
    } else if (start_row - end_row == -1 * (start_col - end_col)) {
        diagonalBoundary(start_r, start_c, end_r, end_c);
        cur_row = *start_r, cur_col = *start_c;
        int counter = 0; // top-right to bottom-left
        while (counter <= start_col - end_col) {
            canvas[cur_row][cur_col] = shade;
            cur_row++;
            cur_col--;
            counter++;
        }
    }

    // Draw only perfectly horizontal or vertical lines
    if (start_row == end_row || start_col == end_col) {
        holdBoundary(start_r, start_c, end_r, end_c);
        cur_row = *start_r, cur_col = *start_c;
        if (start_row <= end_row && start_col == end_col) { // From top to bottom
            while (cur_row <= end_row) {
                canvas[cur_row][cur_col] = shade;
                cur_row++;
            }
        } else if (start_col <= end_col && start_row == end_row) { // From left to right
            while (cur_col <= end_col) {
                canvas[cur_row][cur_col] = shade;
                cur_col++;
            }
        } else if (start_col >= end_col && start_row == end_row) { // From right to left
            while (cur_col >= end_col) {
                canvas[cur_row][cur_col] = shade;
                cur_col--;
            }
        } 
    }
}

// Fill Rectangle
void rectangleFilling(int canvas[N_ROWS][N_COLS], int *start_r, int *start_c, int *end_r, int *end_c, int shade) {
    int start_row = *start_r, start_col = *start_c, end_row = *end_r, end_col = *end_c;
    // if the given command both starts and ends outside the canvas, ignore it
    if (checkLocation(start_row, start_col, end_row, end_col) == -1) return;
    holdBoundary(start_r, start_c, end_r, end_c);
    int cur_row = *start_r, cur_col = *start_c;

    if (*start_r <= *end_r && *start_c <= *end_c) { // Top-left to bottom-right
        while (cur_row <= *end_r) {
            cur_col = *start_c;
            while (cur_col <= *end_c) {
                canvas[cur_row][cur_col] = shade;
                cur_col++;
            }
            cur_row++;
        }
    } else if (*start_r <= *end_r && *start_c >= *end_c) { // Top-right to bottom-left
        while (cur_row <= *end_r) {
            cur_col = *start_c;
            while (cur_col >= *end_c) {
                canvas[cur_row][cur_col] = shade;
                cur_col--;
            }
            cur_row++;
        }
    }
}

//If draw it from the bottom up then flip the start and end, otherwise do nothing
void flipping (int *start_r, int *start_c, int *end_r, int *end_c) {
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

// Boundary for Straight lines and quadrilaterals
// Changes the value beyond the boundary to the maximum or minimum of the border
void holdBoundary(int *start_r, int *start_c, int *end_r, int *end_c) {
    flipping (start_r, start_c, end_r, end_c);

    if (*start_r < 0)          *start_r = 0;
    if (*start_r > N_ROWS)     *start_r = N_ROWS-1;
    if (*start_c < 0)          *start_c = 0;
    if (*start_c > N_COLS)     *start_c = N_COLS-1;
    if (*end_r > N_ROWS)       *end_r = N_ROWS-1;
    if (*end_r < 0)            *end_r = 0;
    if (*end_c > N_COLS)       *end_c = N_COLS-1;
    if (*end_c < 0)            *end_c = 0;
}

// Diagonals' Boundary, Shorten both the protruding rows and columns
void diagonalBoundary(int *start_r, int *start_c, int *end_r, int *end_c) {
    flipping (start_r, start_c, end_r, end_c);
    if (*start_r - *end_r == *start_c - *end_c) {
        // 45° Diagonals ---- top-left to bottom-right

        if (*end_r > N_ROWS-1) { // Lower right corner protruding
            while ((*end_r > N_ROWS-1) || (*end_c > N_COLS-1)) {
                (*end_r)--;
                (*end_c)--;
            }
        } else if (*start_r < 0) { // Top left corner protrusion
            while ((*start_r < 0) || (*start_c < 0)) {
                (*start_r)++;
                (*start_c)++;
            }
        }
    } else if (*start_r - *end_r == -1 * (*start_c - *end_c)) { 
        // 45° Diagonals ---- top-right to bottom-left

        if (*end_r > N_ROWS-1) { // Lower left corner protruding
            while ((*end_r > N_ROWS-1) || (*end_c < 0)) {
                (*end_r)--;
                (*end_c)++;
            }
        } else if (*start_r < 0) { // Top right corner protruding
            while ((*start_r < 0) || (*start_c > N_COLS-1)) {
                (*start_r)++;
                (*start_c)--;
            }
        }
    }
}

// Checking the location of the given command on the canvas
int checkLocation(int start_row, int start_col, int end_row, int end_col) {
    
    // if the given command both starts and ends outside the canvas, ignore it, return -1
    if ((start_row >= 0 && start_row < N_ROWS) && 
        (start_col >= 0 && start_col < N_COLS) && 
          (end_row >= 0 && end_row < N_ROWS) &&
          (end_col >= 0 && end_col < N_COLS)) {
        return 0;
    }
    // if the given command is partially outside the canvas, 
    // only draw the section that is within the canvas
    if ((start_row >= 0 && start_row < N_ROWS) && 
        (start_col >= 0 && start_col < N_COLS)) {
        return 1;
    }
    if ((end_row >= 0 && end_row < N_ROWS) &&
        (end_col >= 0 && end_col < N_COLS)) {
        return 1;
    }
    return -1;       
}