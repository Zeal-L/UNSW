
CC = gcc
CFLAGS = -Wall -Werror -g

all: solveBfs solveDfs solveDfsBacktrack solveKeepLeft

solveBfs: solver.c Maze.c solveBfs.c Queue.c helpers.c
	$(CC) $(CFLAGS) solver.c Maze.c solveBfs.c Queue.c helpers.c -o solveBfs

solveDfs: solver.c Maze.c solveDfs.c Stack.c helpers.c
	$(CC) $(CFLAGS) solver.c Maze.c solveDfs.c Stack.c helpers.c -o solveDfs

solveDfsBacktrack: solver.c Maze.c solveDfsBacktrack.c Stack.c helpers.c
	$(CC) $(CFLAGS) solver.c Maze.c solveDfsBacktrack.c Stack.c helpers.c -o solveDfsBacktrack

solveKeepLeft: solver.c Maze.c solveKeepLeft.c Queue.c helpers.c
	$(CC) $(CFLAGS) solver.c Maze.c solveKeepLeft.c Queue.c helpers.c -o solveKeepLeft

clean:
	rm -f solveBfs solveDfs solveDfsBacktrack solveKeepLeft
