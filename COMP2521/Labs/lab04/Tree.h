// ADT for a tree of records

#ifndef TREE_H
#define TREE_H

#include "List.h"
#include "Record.h"

typedef struct tree *Tree;

/**
 * Creates a new tree that will use the given comparison function
 */
Tree TreeNew(int (*compare)(Record, Record));

/**
 * Frees the given tree. If freeRecords is true, also frees the records.
 */
void TreeFree(Tree t, bool freeRecords);

/**
 * Inserts the given record. Returns true if the record was inserted
 * successfully, or false if there was already a record that compares
 * equal to the given record in the tree (according to the comparison
 * function).
 */
bool TreeInsert(Tree t, Record rec);

/**
 * Deletes the record that compares equal to the given record (according
 * to the comparison function). Returns true if the record was deleted,
 * or false if there was no record that compared equal to the given
 * record.
 */
bool TreeDelete(Tree t, Record rec);

/**
 * Searches for a record that compares equal to the given record
 * (according to the comparison function). Returns the record if it
 * exists, or NULL otherwise.
 */
Record TreeSearch(Tree t, Record rec);

/**
 * Searches for all records between the two given records, inclusive
 * (according to the comparison function) and returns the records in a
 * list in order. Assumes that `lower` is less than `upper`.
 */
List TreeSearchBetween(Tree t, Record lower, Record upper);

/**
 * Displays all records in the given tree in order, one per line
 */
void TreeListInOrder(Tree t);

#endif
