// travel.c ... client for Graph ADT
// Written by John Shepherd, May 2013

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "Graph.h"

// make some assumptions on much data is supplied
#define MAXCITIES 40
#define MAXNAME   20

void usage(char *);
void fatal(char *);
int cityID(char *, char **, int);

int main(int argc, char *argv[])
{
	Graph world;                // graph of world/distances
	FILE *data;                 // file handle
	char  name[MAXNAME + 2];    // input buffer to hold city name lines
	int   ncities;              // how many cities
	char *cityNames[MAXCITIES]; // array of up to MAXCITIES city names
	int   maxflt;               // max length of flights

	// check command-line params
	if (argc != 1 && argc != 3 && argc != 4)
		usage(argv[0]);

	// get array of city names (assumes < MAXCITIES names)
	if ((data = fopen("ha30_name.txt", "r")) == NULL) {
		fatal("Couldn't open file: ha30_name.txt");
	}
	ncities = 0;
	while (fgets(name, MAXNAME, data) != NULL) {
		name[strlen(name) - 1] = '\0';
		cityNames[ncities] = strdup(name);
		ncities++;
	}
	fclose(data);

	// make empty Graph
	world = GraphNew(ncities);

	// get distances and populate Graph edges
	if ((data = fopen("ha30_dist.txt", "r")) == NULL) {
		fatal("Couldn't open file: ha30_dist.txt");
	}
	
	int n = 0, fromCity, toCity, distance;
	while (fscanf(data, "%d", &distance) == 1) {
		fromCity = n / ncities;
		toCity = n % ncities;
		// convert miles to km
		distance = (int) (distance * 100.0 * 1.609344);
		GraphInsertEdge(world, toCity, fromCity, distance);
		n++;
	}
	fclose(data);

	// get a new maximum flight distance
	maxflt = (argc == 4) ? atoi(argv[3]) : 10000;
	if (maxflt == 0)
		maxflt = 10000;

	// do what the user asks for
	if (argc == 1) {
		// only arg is data file => just show graph
		GraphShow(world, cityNames);
	} else {
		// find path from src -> dest
		int src = cityID(argv[1], cityNames, ncities);
		if (src == -1)
			fatal("Source city name invalid");
		int dest = cityID(argv[2], cityNames, ncities);
		if (dest == -1)
			fatal("Destination city name invalid");

		// use graph algorithm to find path
		int *path = calloc((size_t) ncities, sizeof(int));
		if (path == NULL)
			fatal("Can't allocate path array\n");
		int len = findPath(world, src, dest, maxflt, path);

		// display resulting path
		if (len == 0)
			printf("No route from %s to %s\n", argv[1], argv[2]);
		else {
			printf("Least-hops route:\n%s\n", cityNames[path[0]]);
			int i;
			for (i = 1; i < len; i++)
				printf("-> %s\n", cityNames[path[i]]);
		}

		free(path);
	}

	GraphFree(world);
	for (int i = 0; i < ncities; i++)
		free(cityNames[i]);

	return 0;
}

// print usage message and stop
void usage(char *progname)
{
	fprintf(
		stderr,
		"Usage: %s [Start-city Destination-city] [Max-flight-dist]\n",
		progname);
	exit(1);
}

// print message for unrecoverable error and stop
void fatal(char *msg)
{
	fprintf(stderr, "%s\n", msg);
	exit(1);
}

// find city name in table of names
// return index where found, or -1 if not found
int cityID(char *name, char **world, int nC)
{
	int i;
	for (i = 0; i < nC; i++) {
		if (strcmp(world[i], name) == 0)
			return i;
	}
	return -1;
}
