// Zeal L (abc982210694@gmail.com)
// 2020-11-23 10:15:30
// Zid: z5325156
// 
// Print out characters in lower case.


#include <stdio.h>

int lowercase(int c);

// DO NOT CHANGE THIS MAIN FUNCTION
int main(int argc, char *argv[]) {

    // Scan in the first character.
    int c = getchar();

    // Loop until there are no more characters to scan.
    while (c != EOF) {
        // Print the character, in lowercase.
        putchar(lowercase(c));

        // Get the next character.
        c = getchar();
    }

    return 0;
}

// Returns the specified character `c`, in lowercase.
int lowercase(int c) {
    if (c >= 'A' && c <= 'Z') {
        return c + 32;
    }
    return c;
}
