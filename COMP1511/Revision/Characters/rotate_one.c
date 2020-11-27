// Zeal L (abc982210694@gmail.com)
// 2020-11-23 10:24:32
// Zid: z5325156
// 
// Rotate a character by one -- i.e. turn 'a' to 'b', 'b' to 'c', ...
// 'z' to 'a'.


#include <stdio.h>
#include <stdlib.h>

int rotateOne(int c);

// DO NOT CHANGE THIS MAIN FUNCTION
int main(int argc, char *argv[]) {

    // Scan in the first character.
    int c = getchar();

    // Loop until there are no more characters to scan.
    while (c != EOF) {
        // Print the character, "rotated" once.
        putchar(rotateOne(c));

        // Get the next character.
        c = getchar();
    }

    return 0;
}
// END OF MAIN FUNCTION

// "Rotate" the letter by one, i.e. change 'a' to 'b', 'b' to 'c',
// 'z' to 'a'.
int rotateOne(int c) {
    if ((c >= 97 && c <= 122) || (c >= 65 && c <= 90)) {
        if ((c == 122) || (c == 90)) {
            return c-25;
        }
        return c+1;
    }
    return c;
}
