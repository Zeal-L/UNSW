// Binary Search Tree ADT interface ... 

#ifndef BSTREE_H
#define BSTREE_H

#include <stdbool.h>

typedef int Item;      // item is just a key

typedef struct Node *Tree;

Tree newTree();        // create an empty Tree
void freeTree(Tree);   // free memory associated with Tree
void showTree(Tree);   // display a Tree (sideways)

bool TreeSearch(Tree, Item);   // check whether an item is in a Tree
int  TreeHeight(Tree);         // compute height of Tree
int  TreeNumNodes(Tree);       // count #nodes in Tree
Tree TreeInsert(Tree, Item);   // insert a new item into a Tree
Tree TreeDelete(Tree, Item);   // delete an item from a Tree

// internal functions made visible for testing
Tree rotateRight(Tree);
Tree rotateLeft(Tree);
Tree insertAtRoot(Tree, Item);
Tree partition(Tree, int);
Tree rebalance(Tree);

Tree joinTrees(Tree t1, Tree t2);
Tree addTree(Tree t1, Tree t2);

Tree getLeftTree(Tree t);
Tree getRightTree(Tree t);

// printTree
void printTree(Tree t);

#endif

