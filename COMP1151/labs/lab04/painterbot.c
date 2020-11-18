// By Zeal L, September 2020 fourth week in COMP1511
// Zid:z5325156

#include<stdio.h>

int main(void) {
    int canvas[36] = {0};
    int scanned_in_value = 0;
    int i = 0;
    while (i < 36 && scanf("%d", &scanned_in_value) == 1) {
        canvas[scanned_in_value] = 1;
        i++;
    }
    int counter = 0;
    while (counter < 36) {
        printf("%d", canvas[counter]);
        counter++;
    }
    printf("\n");
    return 0;
}