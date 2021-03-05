// Zeal L (abc982210694@gmail.com)
// 2020-10-27 18:40:44
// Seventh week in COMP1511
// Zid:z5325156

#include <stdio.h>
#include <string.h>
#include <stdbool.h>

bool is_vowel(int character);

int main(void) {

    int character = getchar();
    while (character != EOF) {
        if (is_vowel(character) == false) {
            putchar(character);
        }
        character = getchar();
    }

    return 0;
}

bool is_vowel(int character){
    if (character == 'a' || 
        character == 'e' || 
        character == 'i' || 
        character == 'o' || 
        character == 'u') {
        return true;
    } else {
        return false;
    }
}