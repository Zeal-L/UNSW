//
// COMP1521 21T2 -- Assignment 1 -- Snake!
// <https://www.cse.unsw.edu.au/~cs1521/21T2/assignments/ass1/index.html>
//
// 2021-06-24    v1.0    Team COMP1521 <cs1521@cse.unsw.edu.au>
//

#include <math.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

// Macro-defined constants:
#define N_COLS        15
#define N_ROWS        15
#define MAX_SNAKE_LEN (N_COLS * N_ROWS)

#define EMPTY      0
#define SNAKE_HEAD 1
#define SNAKE_BODY 2
#define APPLE      3

#define NORTH 0
#define EAST  1
#define SOUTH 2
#define WEST  3

// Prototypes --- major game operations:
void init_snake(void);
void update_apple(void);
bool update_snake(int direction);
bool move_snake_in_grid(int new_head_row, int new_head_col);
void move_snake_in_array(int new_head_row, int new_head_col);

// Prototypes --- utility functions:
void set_snake(int row, int col, int body_piece);
void set_snake_grid(int row, int col, int body_piece);
void set_snake_array(int row, int col, int nth_body_piece);
void print_grid(void);
int input_direction(void);
int get_d_row(int direction);
int get_d_col(int direction);
void seed_rng(unsigned int seed);
unsigned int rand_value(unsigned int n);

// Constants:
const char symbols[4] = {'.', '#', 'o', '@'};

// Globals:
int8_t grid[N_ROWS][N_COLS] = { EMPTY };

int8_t snake_body_row[MAX_SNAKE_LEN] = { EMPTY };
int8_t snake_body_col[MAX_SNAKE_LEN] = { EMPTY };
int snake_body_len = 0;
int snake_growth   = 0;
int snake_tail     = 0;

// Code:

// `main' (not provided):
// Run the main game loop!
int main(void) {
	init_snake();
	update_apple();

	int direction;
	do {
		print_grid();
		direction = input_direction();
	} while (update_snake(direction));

	int score = snake_body_len / 3;
	printf("Game over! Your score was %d\n", score);

	return 0;
}


// `init_snake' (not provided):
// Set the snake's initial location.
void init_snake(void) {
	set_snake(7, 7, SNAKE_HEAD);
	set_snake(7, 6, SNAKE_BODY);
	set_snake(7, 5, SNAKE_BODY);
	set_snake(7, 4, SNAKE_BODY);
}


// `update_apple' (not provided):
// Pick a random new location to place an apple.
void update_apple(void) {
	int apple_row;
	int apple_col;

	do {
		apple_row = rand_value(N_ROWS);
		apple_col = rand_value(N_COLS);
	} while (grid[apple_row][apple_col] != EMPTY);

	grid[apple_row][apple_col] = APPLE;
}


// `update_snake' (not provided):
// Move the snake one step in `direction' by updating the snake
// locations on the grid and in the array.  Handle consuming apples.
// Trigger a game-over if we wander off the edges of the board.
bool update_snake(int direction) {
	int d_row = get_d_row(direction);
	int d_col = get_d_col(direction);

	int head_row = snake_body_row[0];
	int head_col = snake_body_col[0];

	grid[head_row][head_col] = SNAKE_BODY;

	int new_head_row = head_row + d_row;
	int new_head_col = head_col + d_col;

	if (new_head_row < 0)       return false;
	if (new_head_row >= N_ROWS) return false;
	if (new_head_col < 0)       return false;
	if (new_head_col >= N_COLS) return false;

	// Check if there is an apple where the snake's head will be
	// *before* we move the snake, and thus overwrite the apple.
	bool apple = (grid[new_head_row][new_head_col] == APPLE);

	snake_tail = snake_body_len - 1;

	if (! move_snake_in_grid(new_head_row, new_head_col)) {
		return false;
	}

	move_snake_in_array(new_head_row, new_head_col);

	if (apple) {
		snake_growth += 3;
		update_apple();
	}

	return true;
}


// `move_snake_in_grid' (not provided):
// Paint the snake onto the grid, moving the head along by a step,
// and removing tail segments.  Fail if this move would cause us
// to run into our own body.
bool move_snake_in_grid(int new_head_row, int new_head_col) {
	if (snake_growth > 0) {
		snake_tail++;

		snake_body_len++;
		snake_growth--;
	} else {
		int tail = snake_tail;

		int tail_row = snake_body_row[tail];
		int tail_col = snake_body_col[tail];

		grid[tail_row][tail_col] = EMPTY;
	}

	if (grid[new_head_row][new_head_col] == SNAKE_BODY) {
		return false;
	}

	grid[new_head_row][new_head_col] = SNAKE_HEAD;
	return true;
}


// `move_snake_in_array':
// Update record of where the snake's body segments are, when the head
// is now in a new location.
void move_snake_in_array(int new_head_row, int new_head_col) {
	for (int i = snake_tail; i >= 1; i--) {
		set_snake_array(snake_body_row[i - 1], snake_body_col[i - 1], i);
	}

	set_snake_array(new_head_row, new_head_col, 0);
}


////////////////////////////////////////////////////////////////////////
///
/// The following functions are already implemented in assembly for you.
///
/// You may find it very useful to read through these functions in C and
/// in assembly, but you do not need to do so.
///

// `set_snake' (provided):
// Set up the snake by painting it onto the grid and by recording where
// that piece of the body was.  Only really used in `init_snake'.
void set_snake (int row, int col, int body_piece)
{
	set_snake_grid(row, col, body_piece);
	set_snake_array(row, col, snake_body_len);
	snake_body_len++;
}

// `set_snake_grid' (provided):
// Place `body_piece' into the grid at `row' and `col'.
void set_snake_grid(int row, int col, int body_piece) {
	grid[row][col] = body_piece;
}

// `set_snake_array' (provided):
// Record that the nth piece of the snake's body is at `row' and `col'.
void set_snake_array(int row, int col, int nth_body_piece) {
	snake_body_row[nth_body_piece] = row;
	snake_body_col[nth_body_piece] = col;
}

// `print_grid' (provided):
// Draw the whole grid to the screen.
void print_grid(void) {
	putchar('\n');

	for (int i = 0; i < N_ROWS; i++) {
		for (int j = 0; j < N_COLS; j++) {
			char symbol = symbols[grid[i][j]];
			putchar(symbol);
		}

		putchar('\n');
	}
}


int last_direction = EAST;

// `input_direction' (provided):
// Read in the next direction that the user wants to move in.
// Handles invalid input by telling the user their input was bad.
// Handles inputs that the snake cannot move in by going bonk.
int input_direction(void) {
    int direction;
    do {
        if ((direction = getchar()) == EOF) {
            exit (0);
		}

        switch (direction) {
			case 'w': direction = NORTH; break;
			case 'a': direction = WEST;  break;
			case 's': direction = SOUTH; break;
			case 'd': direction = EAST;  break;

			case '\n': continue;

			case '\0':
			case '\004':
				exit(0);

			default: {
				printf("invalid direction: %c\n", direction);
				continue;
			}
		}

		if (
			0 <= direction && direction <= 3 &&
			abs(last_direction - direction) != 2
		) {
            last_direction = direction;
            return direction;
        }

        printf("bonk! cannot turn around 180 degrees\n");
    } while (true);
}


// `get_d_row' (provided):
// Determine the delta-row we want to move to.
int get_d_row(int direction) {
	if (direction == SOUTH) {
		return 1;
	} else if (direction == NORTH) {
		return -1;
	} else {
		return 0;
	}
}

// `get_d_col' (provided):
// Determine the delta-column we want to move to.
int get_d_col(int direction) {
	if (direction == EAST) {
		return 1;
	} else if (direction == WEST) {
		return -1;
	} else {
		return 0;
	}
}


///
/// A very simple pseudo-random number generator.
///
/// `rand_seed', `seed_rng', and `rand_value' implement a pseudo-random
/// number generator --- specifically, a linear congruential generator.
/// (You may like to read more about randomness and random numbers ---
/// it's very interesting!)
///

unsigned int rand_seed = 0;

// `seed_rng' (provided):
// Set the initial seed for our simple pseudo-random number generator.
// This is a bit like `srand(3)', but we can't use that on SPIM.
void seed_rng(unsigned int seed) {
	rand_seed = seed;
}

// `rand_value' (provided):
// Get a random number between 0 and `n', and mix in some randomness.
// This is a bit like `rand(3)', but we can't use that on SPIM.
unsigned int rand_value(unsigned int n) {
	rand_seed = (rand_seed * 1103515245 + 12345) & 0x7FFFFFFF;
	return rand_seed % n;
}
