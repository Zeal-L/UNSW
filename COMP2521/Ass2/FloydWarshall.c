// Floyd Warshall ADT interface
// COMP2521 Assignment 2

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>

#include "FloydWarshall.h"
#include "Graph.h"

static ShortestPaths spsnew(int num);

/**
 * Finds all shortest paths between all pairs of nodes.
 * 
 * The  function  returns  a 'ShortestPaths' structure with the required
 * information:
 * - the number of vertices in the graph
 * - distance matrix
 * - matrix of intermediates (see description above)
 */
ShortestPaths FloydWarshall(Graph g) {
	assert(g != NULL);
	int num = GraphNumVertices(g);
	ShortestPaths sps = spsnew(num);

	for (int u = 0; u < num; u++) {
		AdjList l = GraphOutIncident(g, u);
		while (l != NULL) {
			sps.dist[u][l->v] = l->weight;
			sps.next[u][l->v] = l->v;
			l = l->next;
		}
	}

	for (int v = 0; v < num; v++) {
		sps.dist[v][v] = 0;
		sps.next[v][v] = -1;
	}

	// Standard Floyd-Warshall implementation.
	for (int k = 0; k < num; k++) {
		for (int i = 0; i < num; i++) {
			for (int j = 0; j < num; j++) {
				// Because INFINITY is not truly infinite, we skip this operation in order 
				// to avoid large negative numbers due to exceeding the range of int types.
				if (sps.dist[i][k] == INFINITY || sps.dist[k][j] == INFINITY) continue;
				// Edge Relaxation.
				if (sps.dist[i][j] > sps.dist[i][k] + sps.dist[k][j]) {
					sps.dist[i][j] = sps.dist[i][k] + sps.dist[k][j];
					sps.next[i][j] = sps.next[i][k];
				}
			}
		}
	}

	return sps;
}

static ShortestPaths spsnew(int num) {
	ShortestPaths sps;
	sps.numNodes = num;
	sps.dist = malloc(num * sizeof(int *));
	sps.next = malloc(num * sizeof(int *));
	if (!sps.dist || !sps.next) {
        fprintf(stderr, "error: out of memory");
        exit(EXIT_FAILURE);
    }

	for (int i = 0; i < num; i++) {
		sps.dist[i] = malloc(num * sizeof(int));
		sps.next[i] = malloc(num * sizeof(int));
		if (!sps.dist[i] || !sps.next[i]) {
            fprintf(stderr, "error: out of memory");
            exit(EXIT_FAILURE);
        }
		for (int j = 0; j < num; j++) {
			// Array of minimum distances initialized to INFINITY.
			sps.dist[i][j] = INFINITY;
			// Array of the next vertex along the path from v to itself initialized to -1.
			sps.next[i][j] = -1;
		}
	}

	return sps;
}

/**
 * This  function  is  for  you to print out the ShortestPaths structure
 * while you are debugging/testing your implementation. 
 * 
 * We will not call this function during testing, so you may  print  out
 * the  given  ShortestPaths  structure in whatever format you want. You
 * may choose not to implement this function.
 */
void showShortestPaths(ShortestPaths sps) {

}

/**
 * Frees  all  memory associated with the given ShortestPaths structure.
 * We will call this function during testing, so you must implement it.
 */
void freeShortestPaths(ShortestPaths sps) {
	for (int i = 0; i < sps.numNodes; i++) {
		free(sps.dist[i]);
		free(sps.next[i]);
	}
	free(sps.dist);
	free(sps.next);
}

