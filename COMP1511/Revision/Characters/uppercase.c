// Zeal L (abc982210694@gmail.com)
// 2020-11-23 10:24:17
// Zid: z5325156
// 
// Convert a character to uppercase.


#include <stdio.h>

int uppercase(int c);

// DO NOT CHANGE THIS MAIN FUNCTION
int main(int argc, char *argv[]) {

    // Get the character
    int c = getchar();

    // Loop until end of characters
    while (c != EOF) {
        // print the character in uppercase
        putchar(uppercase (c));

        // get the next character
        c = getchar();
    }

    return 0;
}
// END OF MAIN FUNCTION

int uppercase(int c) {
    if (c >= 97 && c <= 122) {
        return c - 32;
    }
    return c;
}
