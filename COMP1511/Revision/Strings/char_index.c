// Zeal L (abc982210694@gmail.com)
// 2020-11-23 10:52:24
// Zid: z5325156
// 
// Find the index of a character in a given string.


#include <stdio.h>

#define BUFFER_LENGTH 1024
#define NOT_IN_STRING -1

void read_line(int buffer_len, char *buffer);
int char_index(int c, char *string);

// DO NOT CHANGE THIS MAIN FUNCTION
int main(int argc, char *argv[]) {
    // Declare a buffer
    char buffer[BUFFER_LENGTH] = {0};

    // Read in a line...
    printf("Enter a line: ");
    read_line(BUFFER_LENGTH, buffer);

    // Get a character
    printf("Enter a character: ");
    int ch;
    ch = getchar();

    // Find and print character index or "not in string"
    int index = char_index(ch, buffer);
    if (index == NOT_IN_STRING) {
        printf("Character '%c' is not in the string.\n", ch);
    } else {
        printf("Index of character '%c': %d\n", ch, index);
    }

    return 0;
}


// Read a line of input into `buffer`, excluding the newline;
// ensures that `buffer` is a null-terminated string.
void read_line(int buffer_len, char *buffer) {
    int temp = 0;
    if (buffer_len == 1) {
        buffer[0] = 0;
    } else {
        for (int i = 0; ((temp = getchar()) != 10) && (i+1 < buffer_len); i++) {
            buffer[i] = temp;
            buffer[i+1] = 0;
        }
    }
}

// Return the index of the first occurrence of
// character `c` in the string, or `NOT_IN_STRING`
int char_index(int c, char *string) {
    int index = 0;
    while (string[index] != '\0') {
        if (string[index] == c) {
            return index;
        }
        index++;
    }
    return NOT_IN_STRING;
}
