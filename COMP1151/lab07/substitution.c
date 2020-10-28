// Zeal L (abc982210694@gmail.com)
// 2020-10-27 21:29:32
// Seventh week in COMP1511
// Zid:z5325156
//
// reads characters from its input and writes the characters
// to its output encrypted with a Substitution cipher.


#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int substitutionCipher(int character, char argv[]);

int main(int argc, char *argv[]) {
    
    int character = getchar();
    while (character != EOF) {
    
        putchar(substitutionCipher(character, argv[1]));
        character = getchar();
    }

    return 0;
}

int substitutionCipher(int character, char argv[]) {

    if ((character >= 'a' && character <= 'z')) {
        int position = character - 'a';
        return argv[position];
    }

    if ((character >= 'A' && character <= 'Z')) {
        int position = character - 'A';
        return argv[position]-32;
    }

    return character;
}