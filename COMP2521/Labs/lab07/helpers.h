
#ifndef HELPERS_H
#define HELPERS_H

#include <stdbool.h>

#include "Cell.h"

/**
 * Allocates  and  returns a 2D matrix of booleans with the given number
 * of rows and columns. All entries are initialised to false. It is  the
 * user's responsibility to call `freeBoolMatrix` to free the matrix.
 */
bool **createBoolMatrix(int nRows, int nCols);

/**
 * Frees the given boolean matrix.
 */
void freeBoolMatrix(bool **matrix);

/**
 * Allocates  and  returns  a 2D matrix of Cells with the give number of
 * rows and columns. All entries are initialised to (0, 0).  It  is  the
 * user's responsibility to call `freeCellMatrix` to free the matrix.
 */
Cell **createCellMatrix(int nRows, int nCols);

/**
 * Frees the given Cell matrix.
 */
void freeCellMatrix(Cell **matrix);

#endif
