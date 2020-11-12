#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include "list.h"

struct list {
    struct node *head;
};

struct node {
    struct node *next;
    int          data;
};

//  print a linked list in this format:
// 17 -> 34 -> 51 -> 68 -> X
void print_list(List l) {
    struct node *n = l->head;
    while (n != NULL) {
        printf("%d -> ", n->data);
        n = n->next;
    }
    printf("X\n");
}


// create linked list from array of strings
List nums_to_list(int len, int nums[]) {
    List l = malloc(sizeof (struct list));
    l->head = NULL;
    int i = len - 1;
    while (i >= 0) {
        struct node *n = malloc(sizeof (struct node));
        assert(n != NULL);
        n->next = l->head;
        n->data = nums[i];
        l->head = n;

        i--;
    }
    return l;
}
