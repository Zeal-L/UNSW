
#ifndef MAZE_H
#define MAZE_H

#include <stdbool.h>

#include "Cell.h"

typedef struct maze *Maze;

/**
 * Reads in a maze from the given file. The file must be formatted as
 * follows:
 *
 *     The first line must begin with two integers:
 *     1. The height of the maze (H)
 *     2. The width of the maze (W)
 *
 *     The next `H` lines must contain an ASCII representation of the
 *     maze, with a # representing a wall cell and a space representing
 *     a path cell. Each of these lines should contain `W` of these
 *     characters - additional characters will be ignored.
 *
 *     The next line must begin with two integers:
 *     1. The 0-indexed row number of the starting cell
 *     2. The 0-indexed column number of the starting cell
 *     Additionally, the starting cell must not be a wall cell.
 *
 *     The next line must begin with two integers:
 *     1. The 0-indexed row number of the exit cell
 *     2. The 0-indexed column number of the exit cell
 *     Additionally, the exit cell must not be a wall cell.
 *
 *     The rest of the file may contain anything, such as comments.
 *
 * Returns the maze if it was read successfully, or NULL otherwise.
 */
Maze MazeRead(FILE *fp);

/**
 * Frees all resources associated with the given maze
 */
void MazeFree(Maze m);

/**
 * Gets the height of the maze
 */
int  MazeHeight(Maze m);

/**
 * Gets the width of the maze
 */
int  MazeWidth(Maze m);

/**
 * Gets the starting cell of the given maze
 */
Cell MazeGetStart(Maze m);

/**
 * Returns true if the given cell is a wall, and false otherwise
 */
bool MazeIsWall(Maze m, Cell c);

/**
 * Visits the given cell and displays the new state of the maze. Returns
 * true if the given cell was the exit, and false otherwise. Visiting a
 * wall cell is not permitted. Visiting the same cell twice is
 * permitted.
 */
bool MazeVisit(Maze m, Cell c);

/**
 * Marks the given cell as part of the solution path and displays the
 * new state of the maze. Marking a wall cell is not permitted. Marking
 * the same cell twice has no effect, but is permitted.
 */
void MazeMarkPath(Maze m, Cell c);

/**
 * Set the pause (in milliseconds) after the maze is displayed
 */
void MazeSetDisplayPause(int ms);

#endif
