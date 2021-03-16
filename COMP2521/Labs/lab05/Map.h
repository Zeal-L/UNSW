// A Map ADT that maps strings to integers

#ifndef MAP_H
#define MAP_H

#include <stdbool.h>

typedef struct map *Map;

// Creates a new map
// Complexity: O(1)
Map  MapNew(void);

// Frees all memory allocated for the given map
// Complexity: O(n)
void MapFree(Map m);

// Adds  a  key-value  pair to the map. If the key already exists in the
// map, its value is replaced with the given value. Makes a copy of  the
// key.
// Complexity: Assume O(log n) (even though it isn't)
void MapSet(Map m, char *key, int value);

// Checks if the map contains the given key
// Complexity: Assume O(log n) (even though it isn't)
bool MapContains(Map m, char *key);

// Gets  the  value associated with the given key. The key is assumed to
// exist.
// Complexity: Assume O(log n) (even though it isn't)
int  MapGet(Map m, char *key);

#endif

