// Zeal L (abc982210694@gmail.com)
// 2020-10-30 17:42:49
// Seventh week in COMP1511
// Zid:z5325156


#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define MAX_LINE_LENGTH 100

int main(void) {

    char characters[MAX_LINE_LENGTH] = {0};
    fgets(characters, MAX_LINE_LENGTH, stdin);

    int i = 0;
    while ((characters[i] != '\0') && ((characters[i+1] != '\n') && (characters[i+1] != '\0'))) {
        
        if (characters[i] < characters[i+1]) {
            putchar(characters[i]);

        } else if (characters[i] == characters[i+1]) {
            putchar(characters[i]);

        } else if (characters[i] > characters[i+1]) {
            putchar(characters[i+1]);
        }
        i += 2;
    }
    printf("\n");
    return 0;
}