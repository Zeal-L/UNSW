
#include "list.h"

// Your task is to write a function, reverseDLList, that reverses a 
// given doubly linked list. You should not change the values in any 
// nodes or create any new nodes - instead, you should rearrange the 
// nodes of the given list.

void listReverse(List l) {
	Node prev = NULL;
    Node curr = l->head;
    
    while (curr) {
        Node next = curr->next;
        curr->next = prev;
        prev = curr;
        curr = next;
    }

    l->head = prev;
}

// 需要注意的是，最后返回反转后链表的头节点时，应该是prev，
// 而不是current，因为最终退出循环时，current保存的是原链表的最后一个结点，
// 其next指针为NULL，而prev才是反转后链表的头节点。