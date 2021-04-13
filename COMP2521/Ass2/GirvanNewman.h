// Girvan-Newman Algorithm for community discovery
// COMP2521 Assignment 2

// Note: You MUST NOT modify this file.

#ifndef GIRVAN_NEWMAN_H
#define GIRVAN_NEWMAN_H

#include <stdbool.h>

#include "Graph.h"

typedef struct DNode *Dendrogram;

typedef struct DNode {
	int vertex; // This value is irrelevant in non-leaf dendrogram nodes
	Dendrogram left;
	Dendrogram right;
} DNode;

/**
 * Generates  a Dendrogram for the given graph g using the Girvan-Newman
 * algorithm. 
 * 
 * The function returns a 'Dendrogram' structure.
 */
Dendrogram GirvanNewman(Graph g);

/**
 * Frees all memory associated with the given Dendrogram  structure.  We
 * will call this function during testing, so you must implement it.
 */
void freeDendrogram(Dendrogram d);

#endif

