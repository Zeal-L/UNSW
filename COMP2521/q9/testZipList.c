// Main program for testing zipList

// !!! DO NOT MODIFY THIS FILE !!!

#include <stdio.h>
#include <stdlib.h>

#include "list.h"

List zipList(List l1, int x, List l2, int y);

int main(int argc, char *argv[]) {
    char buffer[1024];

    char *line1 = fgets(buffer, sizeof(buffer), stdin);
    List list1 = ListRead(line1);
    printf("list1: ");
    ListShow(list1);

    char *line2 = fgets(buffer, sizeof(buffer), stdin);
    List list2 = ListRead(line2);
    printf("list2: ");
    ListShow(list2);

    int x, y;
    if (scanf("%d %d", &x, &y) != 2) {
        printf("error: failed to read x and y\n");
        return 1;
    }
    printf("x: %d, y: %d\n", x, y);

    List zipped = zipList(list1, x, list2, y);
    printf("zipped list: ");
    ListShow(zipped);

    ListFree(list1);
    ListFree(list2);
    ListFree(zipped);
}

