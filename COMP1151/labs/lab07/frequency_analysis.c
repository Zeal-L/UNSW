// Zeal L (abc982210694@gmail.com)
// 2020-10-28 12:47:53
// Seventh week in COMP1511
// Zid:z5325156
//
// reads characters from its input until end of input.
// It should then print the occurrence frequency for each of the 26 letters 'a'..'z'.

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define LENGTH 26

int main(void) {
    
    int character_counts[LENGTH] = {0};  
    int character = getchar();
    double total = 0.0;
    int index = 0;
    while (character != EOF) {
        if (character >= 'a' && character <= 'z') {
            index = character - 'a';
            character_counts[index]++;
            total++;
        }
        if (character >= 'A' && character <= 'Z') {
            index = character - 'A';
            character_counts[index]++;
            total++;
        }
        character = getchar();
    }

    for (int i = 0; i < LENGTH; i++) {
        printf("'%c' %lf %d\n", 'a' + i, character_counts[i]/total, character_counts[i]);
    }
    return 0;
}