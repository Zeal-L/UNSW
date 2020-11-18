// Zeal L (abc982210694@gmail.com)
// 2020-11-13 18:05:33
// Ninth week in COMP1511
// Zid:z5325156
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>

struct node {
    struct node *next;
    int          data;
};

int length(struct node *head);
struct node *strings_to_list(int len, char *strings[]);

// DO NOT CHANGE THIS MAIN FUNCTION

int main(int argc, char *argv[]) {
    // create linked list from command line arguments
    struct node *head = strings_to_list(argc - 1, &argv[1]);

    int result = length(head);
    printf("%d\n", result);

    return 0;
}


// Return the length of the linked list pointed by head
int length(struct node *head) {
    struct node *curr = head;
    int counter = 0;
    while (curr != NULL){
        counter++;
        curr = curr->next;
    }

    return counter;
}


// DO NOT CHANGE THIS FUNCTION

// create linked list from array of strings
struct node *strings_to_list(int len, char *strings[]) {
    struct node *head = NULL;
    for (int i = len - 1; i >= 0; i = i - 1) {
        struct node *n = malloc(sizeof (struct node));
        assert(n != NULL);
        n->next = head;
        n->data = atoi(strings[i]);
        head = n;
    }
    return head;
}
