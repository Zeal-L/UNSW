
#include <stdio.h>
#include <stdlib.h>

#include "Graph.h"

static int dfsPathCheck(Graph g, int src, int dest, int *visited);

int numReachable(Graph g, int src) {
	int num_R = 0;
	int num = GraphNumVertices(g);
	int *visited = calloc(num, sizeof(int));

	for (int i = 0; i < num; i++) {
		if (dfsPathCheck(g, src, i, visited)) {
			num_R++;
		}
		for (int j = 0; j < num; j++) visited[j] = 0;
	}
	
	free(visited);
	return num_R;
}

static int dfsPathCheck(Graph g, int src, int dest, int *visited) {
	if (src == dest) return 1;

	for (int i = 0; i < GraphNumVertices(g); i++) {
		if (GraphIsAdjacent(g, src, i)) {
			if (visited[i] == 0) {
				visited[i] = 1;
				if (i == dest) return 1;
				else if (dfsPathCheck(g, i, dest, visited)) return 1;
			}
		}
	}
	return 0;
}
