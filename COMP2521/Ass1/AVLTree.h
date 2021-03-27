// ADT for an AVL tree of records

#ifndef TREE_H
#define TREE_H

#include "List.h"
#include "Record.h"

typedef struct tree *Tree;

/**
 * Creates a new tree that will use the given comparison function
 */
Tree   TreeNew(int (*compare)(Record, Record));

/**
 * Frees the given tree. If freeRecords is true, also frees the records.
 */
void   TreeFree(Tree t, bool freeRecords);

/**
 * Searches  the  AVL tree for a record that compares equal to the given
 * record (according to the comparison function).  Returns the record if
 * it exists, or NULL otherwise.
 */
Record TreeSearch(Tree t, Record rec);

/**
 * Inserts the given record into the AVL tree.
 * You  must use the proper AVL insertion algorithm, as discussed in the
 * lectures.
 * The time complexity of this function must be O(log n).
 * Returns true if the record was inserted  successfully,  or  false  if
 * there was already a record that compares equal to the given record in
 * the tree (according to the comparison function).
 */
bool   TreeInsert(Tree t, Record rec);

/**
 * Searches  for  all  records  between the two given records, inclusive
 * (according to the comparison function) and returns the records  in  a
 * list  in  order.  Returns an empty list if there are no such records.
 * Assumes that `lower` is less than `upper`.
 * The time complexity of this function must be O(log n + m), where m is
 * the length of the returned list.
 */
List   TreeSearchBetween(Tree t, Record lower, Record upper);

/**
 * Returns the smallest record greater than or equal to the given record
 * r (according to the comparison function), or NULL if there is no such
 * record.
 * The time complexity of this function must be O(log n).
 */
Record TreeNext( Tree t, Record r);

#endif

