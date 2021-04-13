
#include <stdio.h>
#include <stdlib.h>

#include "FloydWarshall.h"
#include "GraphRead.h"

static void displayShortestPathsStruct(ShortestPaths sps);

int main(int argc, char* argv[]) {
	if (argc < 2) {
		printf("Usage: ./testFloydWarshall [file]\n");
		return EXIT_FAILURE;
	}
	
	Graph g = readGraph(argv[1]);
	ShortestPaths paths = FloydWarshall(g);
	displayShortestPathsStruct(paths);
	freeShortestPaths(paths);
	GraphFree(g);
}

static void displayShortestPathsStruct(ShortestPaths sps) {
	int i = 0;
	int j = 0;
	printf("Shortest path distances\n");
	for (i = 0; i < sps.numNodes; i++) {
		for (j = 0; j < sps.numNodes; j++) {
			printf("    %d, %d : ", i, j);
			if (sps.dist[i][j] == INFINITY) {
				printf("INF\n");		
			} else {
				printf("%d\n", sps.dist[i][j]);
			}
		}
	}
	
	printf("\nNext vertices\n");
	for (i = 0; i < sps.numNodes; i++) {
		for (j = 0; j < sps.numNodes; j++) {
			printf("    %d, %d : ", i, j);
			if (sps.next[i][j] == -1) {
				printf("X\n");
			} else {			
				printf("%d\n", sps.next[i][j]);
			}
		}
	}
}

