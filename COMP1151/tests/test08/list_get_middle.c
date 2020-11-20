#include <stdio.h>
#include <stdlib.h>
#include <assert.h>

struct node {
    struct node *next;
    int          data;
};

int get_middle(struct node *head);
struct node *strings_to_list(int len, char *strings[]);
void get_length(struct node *head, int *length, int *index, int *x);

// DO NOT CHANGE THIS MAIN FUNCTION

int main(int argc, char *argv[]) {
    // create linked list from command line arguments
    struct node *head = strings_to_list(argc - 1, &argv[1]);

    int result = get_middle(head);
    printf("%d\n", result);

    return 0;
}


// Return middle element of a linked list
// if list contains [6,7,8,9,10]  8 is returned
// if a list has even number of elements, first of middle two elements returned
// if list contains [1,2,3,4] 2 is returned
// list can not be empty
int get_middle(struct node *head) {

    int counter = 0;
    int index = 0;
    int x = 0;
    get_length(head, &counter, &index, &x);
    
    return x;
}

void get_length(struct node *head, int *length, int *index, int *x) {
    if (head->next == NULL) {
        (*x) = head->data;
        return;
    }
    (*length)++;
    (*index)++;
    get_length(head->next, length, index, x);
    (*index)--;
    if ((*index) == (*length) / 2) {
        (*x) = head->data;
    }
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
