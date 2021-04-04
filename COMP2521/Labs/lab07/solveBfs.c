// BFS maze solver

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "Cell.h"
#include "helpers.h"
#include "Maze.h"
#include "Queue.h"

bool findPathBFS(Maze m, Cell src, bool **visited, Cell **path, Queue q);
bool validCell(Maze m, Cell v);
void move(Maze m, Cell src, Cell *v, bool **visited, Cell **path, Queue q);
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
    Queue q = QueueNew();

    MazeSetDisplayPause(40);
    bool found = findPathBFS(m, MazeGetStart(m), visited, path, q);
    
    freeBoolMatrix(visited);
    freeCellMatrix(path);
    QueueFree(q);
    return found ? true : false;
}

bool findPathBFS(Maze m, Cell src, bool **visited, Cell **path, Queue q) {
    visited[src.row][src.col] = true;
    bool found = false;
    QueueEnqueue(q, src);
    while (!found && !QueueIsEmpty(q)) {
        Cell v = QueueDequeue(q);
        if (MazeVisit(m, v)) {
            found = true;
            displayTraceBack(m, path, v);
        } else {
            move(m, v, goUp(v), visited, path, q);
            move(m, v, goRight(v), visited, path, q);
            move(m, v, goDown(v), visited, path, q);
            move(m, v, goLeft(v), visited, path, q);
        }
    }
    return found ? true : false;
}

void move(Maze m, Cell src, Cell *v, bool **visited, Cell **path, Queue q) {
    if (validCell(m, *v) && !MazeIsWall(m, *v) 
        && !visited[v->row][v->col]) {
        visited[v->row][v->col] = true;
        path[v->row][v->col] = src;
        QueueEnqueue(q, *v);
    }
    free(v);
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



