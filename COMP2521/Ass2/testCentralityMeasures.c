/*
 * testCentralityMeasures.c
 * 
 *
 * Includes basic interface to read a graph in from
 * a file and a measure and calls the related functions
 *
 * Feel free to override this with your own tests if
 * you so wish.
 */
#include <stdio.h>
#include <stdlib.h>

#include "CentralityMeasures.h"
#include "Graph.h"
#include "GraphRead.h"

#define BUFF_SIZE 1024

static void printUsage(void);
static void displayEdgeValuesStruct(EdgeValues evs);

int main(int argc, char *argv[]) {
	if (argc != 2) {
		printUsage();
		return EXIT_FAILURE;
	}
	
	Graph g = readGraph(argv[1]);
	EdgeValues evs = edgeBetweennessCentrality(g);
	displayEdgeValuesStruct(evs);
	freeEdgeValues(evs);
	GraphFree(g);
}

static void printUsage(void) {
	printf("Usage: ./testCentralityMeasures [file]\n");
}

static void displayEdgeValuesStruct(EdgeValues evs) {
	int i = 0;
	int j = 0;
	for (i = 0; i < evs.numNodes; i++) {
		for (j = 0; j < evs.numNodes; j++) {
			if (evs.values[i][j] != -1.0) {
				printf("%d, %d : %lf\n", i, j, evs.values[i][j]);
			}
		}
	}
}

