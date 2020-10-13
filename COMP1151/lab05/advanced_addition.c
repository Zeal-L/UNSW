// Zeal L (abc982210694@gmail.com)
// 2020-10-13 18:58:20
// Fifth week in COMP1511
// Zid:z5325156
//
// Add two numbers together, but in an array.

#include <stdio.h>
#include <assert.h>

#define MAX_SIZE 101

int sum(int num_lines, int num_digits, int array[MAX_SIZE][MAX_SIZE]);

// DO NOT CHANGE THIS MAIN FUNCTION
int main(void) {
    int array[MAX_SIZE][MAX_SIZE] = {0};

    // Get the array size.
    int num_digits, num_rows;
    printf("Enter the number of rows (excluding the last): ");
    scanf("%d", &num_rows);
    assert(num_rows > 0 && num_rows < 100);

    printf("Enter the number of digits on each row: ");
    scanf("%d", &num_digits);
    assert(num_digits > 0 && num_digits < MAX_SIZE);

    // Scan in values for the array.
    printf("Enter 2D array values:\n");
    int i = 0;
    while (i < num_rows) {
        int j = 0;
        while (j < num_digits) {
            assert(scanf("%d", &array[i][j]) == 1);
            if (array[i][j] < 0 || array[i][j] > 9) {
                printf("You entered a value not between 0 and 9.\n");
                return 1;
            }
            j++;
        }
        i++;
    }

    int carry = sum(num_rows, num_digits, array);

    int j = 0;
    while (j < num_digits) {
        printf("%d ", array[num_rows][j]);
        j++;
    }
    printf("\n");
    i++;

    if (carry > 0) {
        printf("Carried over: %d\n", carry);
    }

    return 0;
}

// Put the sum of the lines in the array into the last line
// accounting for carrying. Return anything you did not carry.
//
// NOTE: num_lines is the number of lines you are adding together. The
// array has an extra line for you to put the result.
int sum(int num_lines, int num_digits, int array[MAX_SIZE][MAX_SIZE]) {
    int total, cur_row = 0, cur_col = num_digits - 1, carried = 0; // carried number
    // Start with the rightmost column to the leftmost
    while (cur_col >= 0) {
        total = 0;
        // Add up line by line from top to bottom
        while (cur_row < num_lines) {
            total += array[cur_row][cur_col];
            cur_row++;
        }
        // If the result is greater than 9, calculate the carried number and keep the remainder
        if (total > 9) {
            while (total > 9) {
                total -= 10;
                carried++;
            }
            total = total % 10;
        }
        // If the carried number is zero, enter the result directly on the last line
        if (carried == 0) {
            array[cur_row][cur_col] += total;
            // If the current result plus the previous carried number is greater than 9, 
            // then calculate the new carried number and keep the remainder
            if (array[cur_row][cur_col] > 9) {
                while (array[cur_row][cur_col] > 9) {
                    array[cur_row][cur_col] -= 10;
                    carried++;
                }
                array[cur_row][cur_col] = array[cur_row][cur_col] % 10;
            }
        // If not, then enter the remainder and put the carried number at the result of the next column
        } else {
            // If the next column exceeds the last then do not operate, 
            // leaving only the current remainder and then return carried number
            if (cur_col-1 >= 0) {
                array[cur_row][cur_col] += total;
                array[cur_row][cur_col - 1] = carried;
                carried = 0;
            } else {
                array[cur_row][cur_col] += total;
                // If the current result plus the previous carried number is greater than 9, 
                // then calculate the new carried number and keep the remainder
                if (array[cur_row][cur_col] > 9) {
                    while (array[cur_row][cur_col] > 9) {
                        array[cur_row][cur_col] -= 10;
                        carried++;
                    }
                    array[cur_row][cur_col] = array[cur_row][cur_col] % 10;
                }
            }
        }
        // Go on to the next column and zero the row
        cur_row = 0;
        cur_col--;
    }
    return carried;
}
