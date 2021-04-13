// Centrality Measures ADT interface
// COMP2521 Assignment 2

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>

#include "CentralityMeasures.h"
#include "FloydWarshall.h"
#include "Graph.h"

static EdgeValues evsnew(Graph g);

/**
 * Finds  the  edge  betweenness  centrality  for each edge in the given
 * graph and returns the results in a  EdgeValues  structure.  The  edge
 * betweenness centrality of a non-existant edge should be set to -1.0.
 */
EdgeValues edgeBetweennessCentrality(Graph g) {
	assert(g != NULL);
	int num = GraphNumVertices(g);
	EdgeValues evs = evsnew(g);
	ShortestPaths paths = FloydWarshall(g);
	
	for (int s = 0; s < num; s++) {
		for (int t = 0; t < num; t++) {
			// First add one to the edges from s to t that do not pass through other vertices.
			if (paths.next[s][t] == t) evs.values[s][t]++;
			// Then, if there is no direct edge from s to t but it can be reached 
			// through another vertex, add one to each edge in the path separately.
			if (paths.next[s][t] != t && paths.next[s][t] != -1) {
				int next = paths.next[s][t];
				int nnext = paths.next[next][t];
				evs.values[s][next]++;
				while (nnext != -1) {
					evs.values[next][nnext]++;
					next = nnext;
					nnext = paths.next[next][t];
				}
			}
		}
	}

	freeShortestPaths(paths);
	return evs;
}

static EdgeValues evsnew(Graph g) {
	int num = GraphNumVertices(g);
	EdgeValues evs;
	evs.numNodes = num;
	evs.values = malloc(num * sizeof(double *));
	if (evs.values == NULL) {
        fprintf(stderr, "error: out of memory");
        exit(EXIT_FAILURE);
    }

	for (int i = 0; i < num; i++) {
		evs.values[i] = malloc(num * sizeof(double));
		if (evs.values[i] == NULL) {
            fprintf(stderr, "error: out of memory");
            exit(EXIT_FAILURE);
        }
		for (int j = 0; j < num; j++) {
			if (GraphIsAdjacent(g, i, j)) {
				// Set existant edge to 0.0.
				evs.values[i][j] = 0.0;
			} else {
				// Set non-existant edge to -1.0.
				evs.values[i][j] = -1.0;
			}
		}
	}
	
	return evs;
}

/**
 * Prints  the  values in the given EdgeValues structure to stdout. This
 * function is purely for debugging purposes and will NOT be marked.
 */
void showEdgeValues(EdgeValues evs) {

}

/**
 * Frees all memory associated with the given EdgeValues  structure.  We
 * will call this function during testing, so you must implement it.
 */
void freeEdgeValues(EdgeValues evs) {
	for (int i = 0; i < evs.numNodes; i++) free(evs.values[i]);
	free(evs.values);
}


