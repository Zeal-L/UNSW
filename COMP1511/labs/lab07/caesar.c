// Zeal L (abc982210694@gmail.com)
// 2020-10-27 19:29:32
// Seventh week in COMP1511
// Zid:z5325156
//
// reads characters from its input and writes the  
// characters to its output encrypted with a Caesar cipher.

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int caesarCipher(int character, int argument);

int main(int argc, char *argv[]) {

    int argument = strtol(argv[1], NULL, 10);
    
    int character = getchar();
    while (character != EOF) {
    
        putchar(caesarCipher(character, argument));
        character = getchar();
    }

    return 0;
}

int caesarCipher(int character, int argument) {
    if ((character >= 'a' && character <= 'z')) {
        int position = character + argument;
        if (position > 'z') {
            position = (character - 'a' + argument) % 26;
            return 'a' + position;
        } else if (position < 'a') {
            position = (character - 'a' + argument) % 26;
            if (position >= 0) {
                return 'a' + position;
            }
            return 'z' + position+1;
        }
        return position;
    }
    if ((character >= 'A' && character <= 'Z')) {
        int position = character + argument;
        if (position > 'A') {
            position = (character - 'A' + argument) % 26;
            return 'A' + position;
        } else if (position < 'A') {
            position = (character - 'A' + argument) % 26;
            if (position >= 0) {
                return 'A' + position;
            }
            return 'Z' + position+1;
        }
        return position;
    }
    return character;
}