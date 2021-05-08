// ADT for a tree of records

#ifndef TREE_H
#define TREE_H

#include <stdbool.h>

#include "Record.h"

typedef struct tree *Tree;

////////////////////////////////////////////////////////////////////////
// Defined here so that isBST.c has access to these fields

typedef struct node *Node;
struct node {
    Record rec;
    Node   left;
    Node   right;
};

struct tree {
    Node    root;
    int     (*compare)(Record, Record);
};

////////////////////////////////////////////////////////////////////////

/**
 * Creates  a  new tree that will use the given comparison function. The
 * comparison function must take two records and return:
 * - a negative number if the first record is considered to be less than
 *   then second
 * - zero if the records are considered equal
 * - a positive number if the first record is considered to  be  greater
 *   than the second
 */
Tree TreeNew(int (*compare)(Record, Record));

/**
 * Frees the given tree. If freeRecords is true, also frees the records.
 */
void TreeFree(Tree t, bool freeRecords);

/**
 * Inserts  the given record using normal BST insertion using the tree's
 * comparison function. Returns true  if  the  record  was  successfully
 * inserted,  or  false  if  there was already a record in the tree that
 * compares equal to the given record. Assumes that the given tree is  a
 * BST.
 */
bool TreeInsert(Tree t, Record rec);

/**
 * Displays the structure of the given tree
 */
void TreeShow(Tree t);

#endif

