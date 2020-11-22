// Zeal L (abc982210694@gmail.com)
// 2020-11-06 18:36:43
// Eighth week in COMP1511
// Zid:z5325156
// 
// reads command line arguments then prints them out. When it prints out, 
// it will convert all upper case letters to lower case.

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

char *lower(char* letter);

int main(int argc, char *argv[]) {
    for (int i = 1; argv[i] != NULL; i++) {
        printf("%s", lower(argv[i]));
        printf(" ");
    }
    printf("\n");
    return 0;
}

char *lower (char* letter) {
    for (int i = 0; letter[i] != '\0'; i++) {
        if (letter[i] >= 'A' && letter[i] <= 'Z') {
            letter[i] += 32;
        }
    }
    return letter;
}