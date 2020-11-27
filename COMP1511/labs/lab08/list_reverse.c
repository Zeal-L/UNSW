// Zeal L (abc982210694@gmail.com)
// 2020-11-04 20:04:09
// Eighth week in COMP1511
// Zid:z5325156

#include <stdio.h>
#include <stdlib.h>
#include <assert.h>

struct node {
    struct node *next;
    int          data;
};

struct node *reverse(struct node *head);
struct node *strings_to_list(int len, char *strings[]);
void print_list(struct node *head);

// DO NOT CHANGE THIS MAIN FUNCTION

int main(int argc, char *argv[]) {
    // create linked list from command line arguments
    struct node *head = strings_to_list(argc - 1, &argv[1]);

    struct node *new_head = reverse(head);
    print_list(new_head);

    return 0;
}

//
// Place the list pointed to by head into reverse order.
// The head of the list is returned.
//
struct node *reverse(struct node *head) {

    struct node* prev = NULL;
    struct node* curr = head;
    
    while (curr) {
        struct node* next = curr->next;
        curr->next = prev;
        prev = curr;
        curr = next;
    }

    return prev;

    
    // Node *RevereseLr1(Node *node) {
    // if(node==NULL||node->next==NULL)
    //     return node;
    //     Node *nextnode=node->next;
    //     node->next=NULL;
    //     Node *reversenode = RevereseLr1(nextnode);
    //     nextnode->next=node;
    //     return reversenode;
    // }
    
    // 需要注意的是，最后返回反转后链表的头节点时，应该是prev，
    // 而不是current，因为最终退出循环时，current保存的是原链表的最后一个结点，
    // 其next指针为NULL，而prev才是反转后链表的头节点。

    // My old stupid way...
    //
    // if (head == NULL) return head;
    // if (head->next == NULL) return head;
    // struct node *curr = head->next;   // 把【1】存下来
    // struct node *prev = curr;         // 把【1】复制一份
    // struct node *p_prev = NULL;
    // struct node *next = NULL;

    // head->next = p_prev;     // 把原来的head 指向 NULL
    // next = curr->next;       // 先把【2】备份
    // prev->next = head;       // 把【1】 指向 原来的head

    // while (next) {           // next != NULL
    //     curr = next;         // curr 指向【2】
    //     p_prev = prev;       // 把【1】再复制一份
    //     prev = curr;         // 把【2】再复制一份
    //     next = curr->next;   // 先把【3】备份
    //     prev->next = p_prev; // 把【2】指向【1】
    // }
    // return prev;
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

// DO NOT CHANGE THIS FUNCTION
// print linked list
void print_list(struct node *head) {
    printf("[");

    for (struct node *n = head; n != NULL; n = n->next) {
        // If you're getting an error here,
        // you have returned an invalid list
        printf("%d", n->data);
        if (n->next != NULL) {
            printf(", ");
        }
    }
    printf("]\n");
}

