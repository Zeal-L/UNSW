
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include "Cell.h"
#include "helpers.h"

////////////////////////////////////////////////////////////////////////

#define INT2VOIDP(i) (void *)(uintptr_t)(i)
#define VOIDP2INT(ptr) (int)(uintptr_t)(ptr)

////////////////////////////////////////////////////////////////////////

bool **createBoolMatrix(int nRows, int nCols) {
    bool **m = malloc((nRows + 1) * sizeof(bool *));
    if (m == NULL) {
        fprintf(stderr, "error: out of memory");
        exit(EXIT_FAILURE);
    }

    m[0] = INT2VOIDP(nRows);
    for (int i = 1; i <= nRows; i++) {
        m[i] = calloc(nCols, sizeof(bool));
        if (m[i] == NULL) {
            fprintf(stderr, "error: out of memory");
            exit(EXIT_FAILURE);
        }
    }

    return &m[1];
}

void freeBoolMatrix(bool **matrix) {
    int nRows = VOIDP2INT(matrix[-1]);
    for (int i = 0; i < nRows; i++) {
        free(matrix[i]);
    }
    free(&matrix[-1]);
}

////////////////////////////////////////////////////////////////////////

Cell **createCellMatrix(int nRows, int nCols) {
    Cell **m = malloc((nRows + 1) * sizeof(Cell *));
    if (m == NULL) {
        fprintf(stderr, "error: out of memory");
        exit(EXIT_FAILURE);
    }

    m[0] = INT2VOIDP(nRows);
    for (int i = 1; i <= nRows; i++) {
        m[i] = calloc(nCols, sizeof(Cell));
        if (m[i] == NULL) {
            fprintf(stderr, "error: out of memory");
            exit(EXIT_FAILURE);
        }
    }

    return &m[1];
}

void freeCellMatrix(Cell **matrix) {
    int nRows = VOIDP2INT(matrix[-1]);
    for (int i = 0; i < nRows; i++) {
        free(matrix[i]);
    }
    free(&matrix[-1]);
}

////////////////////////////////////////////////////////////////////////
