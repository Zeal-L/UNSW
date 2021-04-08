// Interface  to  the  undirected weighted graph ADT, where vertices are
// identified by an integer between 0 and N - 1, where N is  the  number
// of vertices.

#ifndef GRAPH_H
#define GRAPH_H

typedef struct GraphRep *Graph;

typedef int Vertex;

////////////////////////////////////////////////////////////////////////

/**
 * Creates a new graph with `nV` vertices and no edges
 */
Graph GraphNew(int nV);

/**
 * Frees all resources associated with the given graph
 */
void  GraphFree(Graph g);

/**
 * Inserts  an  edge  between  `v`  and  `w` with the given weight. Does
 * nothing if there is already an edge between `v` and `w`.
 */
void  GraphInsertEdge(Graph g, Vertex v, Vertex w, int weight);

/**
 * Removes an edge between `v` and `w`. Does nothing if there is no edge
 * between `v` and `w`.
 */
void  GraphRemoveEdge(Graph g, Vertex v, Vertex w);

/**
 * Finds  the  shortest path (in terms of the number of hops) from `src`
 * to `dest` such that no edge on the path has weight larger than `max`.
 * Stores  the  path  in the given `path` array including both `src` and
 * `dest` and returns the number of vertices stored in the  path  array.
 * Returns 0 if there is no such path.
 */
int   findPath(Graph g, Vertex src, Vertex dest, int max, int *path);

/**
 * Prints the graph, using the given vertex names
 */
void  GraphShow(Graph g, char **names);

////////////////////////////////////////////////////////////////////////

#endif

