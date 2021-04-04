// Recursive DFS maze solver with backtracking

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "Cell.h"
#include "helpers.h"
#include "Maze.h"

bool RecursiveDFS(Maze m, Cell src, bool **visited, Cell **path);
bool validCell(Maze m, Cell v);
bool move(Maze m, Cell src, Cell *v, bool **visited, Cell **path);
void displayTraceBack(Maze m, Cell **path, Cell v);

Cell *goUp(Cell v);
Cell *goRight(Cell v);
Cell *goDown(Cell v);
Cell *goLeft(Cell v);

bool solve(Maze m) {
    int height = MazeHeight(m);
    int width = MazeWidth(m);
    bool **visited = createBoolMatrix(height, width);
    Cell **path = createCellMatrix(height, width);
    Cell start = MazeGetStart(m);
    MazeVisit(m, start);

    MazeSetDisplayPause(100);
    visited[start.row][start.col] = true;
    bool found = RecursiveDFS(m, start, visited, path);
    
    freeBoolMatrix(visited);
    freeCellMatrix(path);
    return found ? true : false;
}

bool RecursiveDFS(Maze m, Cell src, bool **visited, Cell **path) {

    if (move(m, src, goUp(src), visited, path) || 
        move(m, src, goRight(src), visited, path) || 
        move(m, src, goDown(src), visited, path) || 
        move(m, src, goLeft(src), visited, path)) return true;

    MazeVisit(m, src);
    return false;
}

bool move(Maze m, Cell src, Cell *v, bool **visited, Cell **path) {
    if (validCell(m, *v) && !MazeIsWall(m, *v) 
        && !visited[v->row][v->col]) {
        visited[v->row][v->col] = true;
        path[v->row][v->col] = src;
        if (MazeVisit(m, *v)) {
            displayTraceBack(m, path, *v);
            free(v);
            return true;
        } else {
            Cell temp = *v;
            free(v);
            return RecursiveDFS(m, temp, visited, path);
        }
    }
    free(v);
    return false;
}

void displayTraceBack(Maze m, Cell **path, Cell v) {
    Cell start = MazeGetStart(m);
    MazeMarkPath(m, v);
    Cell back = path[v.row][v.col];
    while (start.row != back.row || start.col != back.col) {
        MazeMarkPath(m, back);
        back = path[back.row][back.col];
    }
    MazeMarkPath(m, start);
}

bool validCell(Maze m, Cell v) {
    if (v.row >= 0 && v.row < MazeHeight(m)
        && v.col >= 0 && v.col < MazeWidth(m)) {
            return true;
        }
    return false;
}

Cell *goUp(Cell v) {
    Cell *up = malloc(sizeof(*up));
    up->col = v.col;
    up->row = v.row - 1;
    return up;
}

Cell *goRight(Cell v) {
    Cell *up = malloc(sizeof(*up));
    up->col = v.col + 1;
    up->row = v.row;
    return up;
}

Cell *goDown(Cell v) {
    Cell *up = malloc(sizeof(*up));
    up->col = v.col;
    up->row = v.row + 1;
    return up;
}

Cell *goLeft(Cell v) {
    Cell *up = malloc(sizeof(*up));
    up->col = v.col - 1;
    up->row = v.row;
    return up;
}




