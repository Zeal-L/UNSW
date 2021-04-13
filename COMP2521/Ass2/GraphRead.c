// Function to read in a graph
// COMP2521 Assignment 2

#include "Graph.h"
#include "GraphRead.h"

#include <stdlib.h>
#include <stdio.h>
#include <assert.h>

Graph readGraph(char* file) {
	// ugly count!
	FILE *f = fopen(file, "r");
	if (f == NULL) {
		fprintf(stderr, "ERROR READING FILE %s\n", file);
		return NULL;
	}
	
	int lines = 0;
	char ch = 0;
	while (!feof(f)) {
		ch = fgetc(f);
		if (ch == '\n') lines++;
	}
	fclose(f);

	// ugly parse!
	f = fopen(file, "r");
	if (f == NULL) {
		fprintf(stderr, "ERROR READING FILE %s\n", file);
		return NULL;
	}
	
	int a = 0;
	int b = 0;
	int c = 0;
	int i = 0;
	int maxVert = -1;
	int **nums = malloc(sizeof(int *) * lines);
	for (i = 0; i < lines; i++) {
		nums[i] = malloc(sizeof(int) * 3);
	}
	
	i = 0;
	while (i < lines) {
		fscanf(f, "%d,", &a);
		fscanf(f, "%d,", &b);
		fscanf(f, "%d",  &c);
		if (a > maxVert) maxVert = a;
		if (b > maxVert) maxVert = b;
		nums[i][0] = a;
		nums[i][1] = b;
		nums[i][2] = c;
		i++;
	}
	fclose(f);

	Graph g = GraphNew(maxVert + 1);
	i = 0;
	while (i < lines) {
		GraphInsertEdge(g, nums[i][0], nums[i][1], nums[i][2]);
		i++;
	}
	
	for (i = 0; i < lines; i++)
		free(nums[i]);
	free(nums);
	return g;
}

