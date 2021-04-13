// Centrality Measures ADT interface
// COMP2521 Assignment 2

// Note: You MUST NOT modify this file.

#ifndef CENTRALITY_MEASURES_H
#define CENTRALITY_MEASURES_H

#include <stdbool.h>

#include "Graph.h"

typedef struct EdgeValues {
	int numNodes;    // The number of vertices in the graph
	double **values; // A matrix of values, one for each edge.
	                 // values[v][w] contains the edge betweenness of
	                 // the edge from v to w.
} EdgeValues;


/**
 * Finds  the  edge  betweenness  centrality  for each edge in the given
 * graph and returns the results in a  EdgeValues  structure.  The  edge
 * betweenness centrality of a non-existant edge should be set to -1.0.
 */
EdgeValues edgeBetweennessCentrality(Graph g);

/**
 * This  function is for you to print out the EdgeValues structure while
 * while you are debugging/testing your implementation. 
 * 
 * We will not call this function during testing, so you may  print  out
 * the  given  EdgeValues structure in whatever format you want. You may
 * choose not to implement this function.
 */
void showEdgeValues(EdgeValues evs);

/**
 * Frees all memory associated with the given EdgeValues  structure.  We
 * will call this function during testing, so you must implement it.
 */
void freeEdgeValues(EdgeValues evs);

#endif

