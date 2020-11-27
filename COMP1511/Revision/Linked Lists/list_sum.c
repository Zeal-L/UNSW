// Zeal L (abc982210694@gmail.com)
// 2020-11-27 17:51:18
// Zid: z5325156
// 
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>

struct node {
    struct node *next;
    int          data;
};

int sum(struct node *head);
struct node *strings_to_list(int len, char *strings[]);

// DO NOT CHANGE THIS MAIN FUNCTION

int main(int argc, char *argv[]) {
    // create linked list from command line arguments
    struct node *head = strings_to_list(argc - 1, &argv[1]);

    int result = sum(head);
    printf("%d\n", result);

    return 0;
}


// Return the sum of the elements in the linked list pointed by head
int sum(struct node *head) {
    int sum = 0;
    while (head) {
        sum += head->data;
        head = head->next;
    }
    return sum;

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
