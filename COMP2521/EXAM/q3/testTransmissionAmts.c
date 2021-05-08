// testTransmissionAmts.c

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>

#include "Graph.h"

void calculateViralTransmission(Graph g, int src, int srcViralLoad,
                                double *trasmissionArray);

int main(void) {
    int nV;
    if (scanf("nV: %d ", &nV) != 1) {
        printf("error: failed to read nV\n");
        return 1;
    }

    int src;
    if (scanf("src: %d ", &src) != 1) {
        printf("error: failed to read src\n");
        return 1;
    }

    int srcViralLoad;
    if (scanf("srcViralLoad: %d ", &srcViralLoad) != 1) {
        printf("error: failed to read srcViralLoad\n");
        return 1;
    }

    printf("nV: %d\nsrc: %d\nsrcViralLoad: %d\n\n",
           nV, src, srcViralLoad);

    Graph g = GraphNew(nV);
    int v, w;
    while (scanf("%d %d", &v, &w) == 2) {
        GraphAddEdge(g, v, w);
        printf("Edge inserted: %d-%d\n", v, w);
    }
    printf("\n");

    double *trasmissionArray = malloc(nV * sizeof(double));
    int i;
    for (i = 0; i < nV; i++) {
        trasmissionArray[i] = -1.0;
    }

    calculateViralTransmission(g, src , srcViralLoad, trasmissionArray);

    printf("Viral load:\n");
    for (i = 0; i < nV; i++) {
        printf(" trasmissionArray[%d] is %10.3lf \n",
               i, trasmissionArray[i]);
    }

    free(trasmissionArray);
    GraphFree(g);
}

