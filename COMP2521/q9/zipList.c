
#include <assert.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>

#include "list.h"

// Worst case time complexity of this solution: O(n)
List zipList(List l1, int x, List l2, int y) {

    List result = ListNew();
    Node new_cur = NULL;
    Node curr1 = l1->first;
    Node curr2 = l2->first;
    if (!x) curr1 = NULL;
    if (!y) curr2 = NULL;
    while (curr1 || curr2) {
        for (int i = 0; i < x; i++) {
            if (!curr1) break;
            if (!result->first) {
                result->first = newNode(curr1->value);
                new_cur = result->first;
                curr1 = curr1->next;
                continue;
            }
            new_cur->next = newNode(curr1->value);
            new_cur = new_cur->next;
            curr1 = curr1->next;
        }
        for (int i = 0; i < y; i++) {
            if (!curr2) break;
            if (!result->first) {
                result->first = newNode(curr2->value);
                new_cur = result->first;
                curr2 = curr2->next;
                continue;
            }
            new_cur->next = newNode(curr2->value);
            new_cur = new_cur->next;
            curr2 = curr2->next;
        }
        // printf("%d\n", new_cur->value);
    }

    return result;
}

