// Zeal L (abc982210694@gmail.com)
// 2020-11-10 21:13:59
// Ninth week in COMP1511
// Zid:z5325156

#include <stdio.h>
#include <stdlib.h>

// Do not edit these structs. You may use them exactly as
// they are but you cannot make changes to them

// A node in a linked list
struct node {
    int data;
    struct node *next;
};

// a list_node in a linked list. Each list_node
// contains a list of nodes.
struct list_node {
    struct node *my_list;
    struct list_node *next;
};

// Treat the linked lists like they're a 2D array
// and return 1 if the first element is repeated
// diagonally through the lists
int has_diagonal(struct list_node *head) {

    int value = head->my_list->data;
    for (int i = 0; head != NULL; i++){
        struct node *curr_list = head->my_list;
        for (int j = 0; curr_list != NULL ;j++){
            if (i == j && curr_list->data != value) {
                return 0;
            }
            curr_list = curr_list->next;
        }
        head = head->next;
    }
    return 1;
}

// This helper function is for the main below and will
// have no effect on your has_diagonal. It does not
// need to be modified.
struct node *make_list(int a, int b, int c);

// This is a main function which could be used
// to test your has_diagonal function.
// It will not be marked.
// Only your has_diagonal function will be marked.
//
// It's recommended to change the int values in this
// main to test whether your has_diagonal is working.
int main(void) {
    struct list_node *head = malloc(sizeof (struct list_node));
    struct list_node *l = head;
    
    // create the first list
    l->my_list = make_list(5, 0, 0);
    
    // create the second list
    l->next = malloc(sizeof (struct list_node));
    l = l->next;
    l->my_list = make_list(0, 5, 0);
    
    // create the third list
    l->next = malloc(sizeof (struct list_node));
    l = l->next;
    l->my_list = make_list(0, 0, 5);
    l->next = NULL;
    
    printf("The result of has_diagonal is: %d\n", has_diagonal(head));
    
    return 0;
}

struct node *make_list(int a, int b, int c) {
    struct node *head = malloc(sizeof (struct node));
    struct node *n = head;
    n->data = a;
    n->next = malloc(sizeof (struct node));
    n = n->next;
    n->data = b;
    n->next = malloc(sizeof (struct node));
    n = n->next;
    n->data = c;
    n->next = NULL;
    
    return head;
}
