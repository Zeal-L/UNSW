// Zeal L (abc982210694@gmail.com)
// 2020-10-27 19:01:53
// Seventh week in COMP1511
// Zid:z5325156
//
// Function to print out a string that has had it's cases swapped.
// swap_case.c

#include <stdio.h>
#include <string.h>

int swap_case(int character);

int main(void) {

    int character = getchar();
    while (character != EOF) {
        putchar(swap_case(character));
        character = getchar();
    }

    return 0;
}

int swap_case(int character) {
    //  - return character in lower case if it is an upper case letter
    if (character >= 'A' && character <= 'Z') {
        return character + 32;
    } 

    //  - return character in upper case if it is an lower case letter
    if (character >= 'a' && character <= 'z') {
        return character - 32;
    }

    //  - return the character unchanged otherwise
    return character;
}
