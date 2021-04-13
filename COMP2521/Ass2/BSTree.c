// Binary Search Tree ADT implementation ... 

#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include "BSTree.h"

#define data(tree)  ((tree)->data)
#define left(tree)  ((tree)->left)
#define right(tree) ((tree)->right)


typedef struct Node {
   int  data;
   Tree left, right;
} Node;


// make a new node containing data
Tree newNode(Item it) {
   Tree new = malloc(sizeof(Node));
   assert(new != NULL);
   data(new) = it;
   left(new) = right(new) = NULL;
   return new;
}

// create a new empty Tree
Tree newTree() {
   return NULL;
}

// free memory associated with Tree
void freeTree(Tree t) {
   if (t != NULL) {
      freeTree(left(t));
      freeTree(right(t));
      free(t);
   }
}

Tree getLeftTree(Tree t) {
	if(t == NULL) return NULL;
	return t->left;
}

Tree getRightTree(Tree t) {
	if(t == NULL) return NULL;
	return t->right;
}


// insert a new item into a Tree
Tree TreeInsert(Tree t, Item it) {
   if (t == NULL)
      t = newNode(it);
   else if (it < data(t))
      left(t) = TreeInsert(left(t), it);
   else if (it > data(t))
      right(t) = TreeInsert(right(t), it);
   return t;
}


// printTree
void printTree(Tree t) {

   if (t == NULL) { return; }

   printTree(t->left);

   if(t->left != NULL) { printf(", "); }   
   printf("%d", t->data);
   if(t->right != NULL) { printf(", "); }
  
   printTree(t->right);
}


// addTree
Tree addTree(Tree t1, Tree t2) {
   	if (t2 == NULL)
      		return t1;

   	Tree t = TreeInsert(t1, t2->data);
	t = addTree(t, t2->left);
	t = addTree(t, t2->right);
	return t;
}



