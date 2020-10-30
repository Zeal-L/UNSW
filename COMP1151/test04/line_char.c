// Zeal L (abc982210694@gmail.com)
// 2020-10-30 17:28:49
// Seventh week in COMP1511
// Zid:z5325156
//
// reads a line from its input then reads an integer n from its input.

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define MAX_LINE_LENGTH 256

int main(void) {

    char characters[MAX_LINE_LENGTH];
    fgets(characters, MAX_LINE_LENGTH, stdin);
    int index = 0;
    scanf("%d", &index);
    printf("The character in position %d is '%c'\n", index, characters[index]);


    return 0;
}