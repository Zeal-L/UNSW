
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>

#include "Cell.h"
#include "Maze.h"

#define CLEAR_SCREEN_ANSI "\e[1;1H\e[2J"

typedef enum {
    NONE,
    VISITED,
    PATH,
} State;

struct maze {
    int     height;
    int     width;
    Cell    start;
    Cell    exit;
    bool  **cells;

    State **state;
};

static int pauseMs = 200;

////////////////////////////////////////////////////////////////////////

static bool readDimensions(Maze m, FILE *fp);
static bool readStart(Maze m, FILE *fp);
static bool readExit(Maze m, FILE *fp);
static bool readCells(Maze m, FILE *fp);
static bool createState(Maze m);

static void freeCells(Maze m);
static void freeState(Maze m);

static void showState(Maze m, Cell c);
static bool isExit(Maze m, Cell c);

static bool validCell(Maze m, Cell c);

////////////////////////////////////////////////////////////////////////

Maze MazeRead(FILE *fp) {
    Maze m = malloc(sizeof(*m));
    if (m == NULL) {
        fprintf(stderr, "error: out of memory\n");
        return NULL;
    }
    
    if (!(readDimensions(m, fp) && readCells(m, fp))) {
    	free(m);
    	return NULL;
    }

    if (!(readStart(m, fp) && readExit(m, fp) && createState(m))) {
        freeCells(m);
        free(m);
        return NULL;
    }

    return m;
}

static bool readDimensions(Maze m, FILE *fp) {
    char *line = NULL;
    size_t n = 0;
    bool res;

    if (!(res = (getline(&line, &n, fp) > 0 &&
            sscanf(line, "%d %d", &m->height, &m->width) == 2))) {
        fprintf(stderr, "error: failed to read maze dimensions\n");
    } else if (!(res = (m->height > 0 && m->width > 0))) {
        fprintf(stderr, "error: invalid maze dimensions\n");
    }

    free(line);
    return res;
}

static bool readCells(Maze m, FILE *fp) {

    //////////////////////////////
    // allocate everything first

    char *line = malloc((m->width + 2) * sizeof(char));
    if (line == NULL) {
        fprintf(stderr, "error: out of memory\n");
        return false;
    }

    m->cells = calloc(m->height, sizeof(bool *));
    if (m->cells == NULL) {
        fprintf(stderr, "error: out of memory\n");
        free(line);
        return false;
    }

    for (int i = 0; i < m->height; i++) {
        m->cells[i] = malloc(m->width * sizeof(bool));
        if (m->cells[i] == NULL) {
            fprintf(stderr, "error: out of memory\n");
            freeCells(m);
            free(line);
            return false;
        }
    }

    //////////////////////////
    // now read in the cells

    size_t n = m->width + 2;
    for (int i = 0; i < m->height; i++) {
        if (getline(&line, &n, fp) < m->width) {
            fprintf(stderr, "error: not enough cells on row %d\n", i);
            freeCells(m);
            free(line);
            return false;
        }

        for (int j = 0; j < m->width; j++) {
            switch (line[j]) {
                case '#': m->cells[i][j] = true;  break;
                case ' ': m->cells[i][j] = false; break;
                default:
                    fprintf(stderr, "error: unknown cell character '%c'\n",
                            line[j]);
                    freeCells(m);
                    free(line);
                    return false;
            }
        }
    }

    free(line);
    return true;
}

static bool readStart(Maze m, FILE *fp) {
    char *line = NULL;
    size_t n = 0;
    bool res;

    if (!(res = (getline(&line, &n, fp) > 0 &&
            sscanf(line, "%d %d", &m->start.row, &m->start.col) == 2))) {
        fprintf(stderr, "error: failed to read starting cell\n");
    } else if (!(res = validCell(m, m->start))) {
        fprintf(stderr, "error: invalid starting cell\n");
    } else if (!(res = !MazeIsWall(m, m->start))) {
        fprintf(stderr, "error: starting cell is a wall cell\n");
    }

    free(line);
    return res;
}

static bool readExit(Maze m, FILE *fp) {
    char *line = NULL;
    size_t n = 0;
    bool res;

    if (!(res = (getline(&line, &n, fp) > 0 &&
            sscanf(line, "%d %d", &m->exit.row, &m->exit.col) == 2))) {
        
        fprintf(stderr, "error: failed to read exit cell\n");
    } else if (!(res = validCell(m, m->exit))) {
        fprintf(stderr, "error: invalid exit cell\n");
    } else if (!(res = !MazeIsWall(m, m->exit))) {
        fprintf(stderr, "error: exit cell is a wall cell\n");
    }

    free(line);
    return res;
}

static bool createState(Maze m) {
    m->state = calloc(m->height, sizeof(State *));
    if (m->state == NULL) {
        fprintf(stderr, "error: out of memory\n");
        return false;
    }

    for (int i = 0; i < m->height; i++) {
        m->state[i] = malloc(m->width * sizeof(State));
        if (m->state[i] == NULL) {
            fprintf(stderr, "error: out of memory\n");
            freeState(m);
            return false;
        }

        for (int j = 0; j < m->width; j++) {
            m->state[i][j] = NONE;
        }
    }

    return true;
}

////////////////////////////////////////////////////////////////////////

void MazeFree(Maze m) {
    freeState(m);
    freeCells(m);
    free(m);
}

static void freeCells(Maze m) {
    for (int i = 0; i < m->height; i++) {
        free(m->cells[i]);
    }
    free(m->cells);
}

static void freeState(Maze m) {
    for (int i = 0; i < m->height; i++) {
        free(m->state[i]);
    }
    free(m->state);
}

////////////////////////////////////////////////////////////////////////

int  MazeHeight(Maze m) {
    return m->height;
}

int  MazeWidth(Maze m) {
    return m->width;
}

Cell MazeGetStart(Maze m) {
    return m->start;
}

bool MazeIsWall(Maze m, Cell c) {
    return m->cells[c.row][c.col];
}

bool MazeVisit(Maze m, Cell c) {
    if (MazeIsWall(m, c)) {
        fprintf(stderr, "error: wall cells cannot be visited\n");
        exit(EXIT_FAILURE);
    }

    m->state[c.row][c.col] = VISITED;

    showState(m, c);

    return (c.row == m->exit.row && c.col == m->exit.col);
}

void MazeMarkPath(Maze m, Cell c) {
    if (MazeIsWall(m, c)) {
        fprintf(stderr, "error: wall cells cannot be marked\n");
        exit(EXIT_FAILURE);
    }

    m->state[c.row][c.col] = PATH;

    showState(m, c);
}

static void showState(Maze m, Cell c) {
    int h = MazeHeight(m);
    int w = MazeWidth(m);

    printf(CLEAR_SCREEN_ANSI);
    for (int row = 0; row < h; row++) {
        for (int col = 0; col < w; col++) {
            if (m->state[row][col] == PATH) {
                printf("\033[43m  \033[0m");
            } else if (row == c.row && col == c.col) {
                printf("\033[41m  \033[0m");
            } else if (m->state[row][col] == VISITED) {
                printf("\033[44m  \033[0m");
            } else if (MazeIsWall(m, (Cell){row, col})) {
                printf("\033[47m  \033[0m");
            } else if (isExit(m, (Cell){row, col})) {
                printf("\033[42m  \033[0m");
            } else {
                printf("\033[40m  \033[0m");
            }
        }
        printf("\n");
    }

    struct timespec ts;
    ts.tv_sec = 0;
    ts.tv_nsec = pauseMs * 1000000;
    nanosleep(&ts, NULL);
}

static bool isExit(Maze m, Cell c) {
    return c.row == m->exit.row && c.col == m->exit.col;
}

void MazeSetDisplayPause(int ms) {
    if (ms >= 0) {
        pauseMs = ms;
    }
}

////////////////////////////////////////////////////////////////////////

static bool validCell(Maze m, Cell c) {
    return (
        c.row >= 0 && c.row < m->height && c.col >= 0 && c.col < m->width
    );
}

