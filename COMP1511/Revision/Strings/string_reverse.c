// Zeal L (abc982210694@gmail.com)
// 2020-11-23 12:15:29
// Zid: z5325156
// 
// gnirts a esreveR (Reverse a string)


#include <stdio.h>
#include <string.h>

void string_reverse(char *buffer);

int main(int argc, char *argv[]) {

    // NOTE: THIS WON'T WORK:
    // char *str = "Hello!"
    // string_reverse(str)
    //
    // str only points to a string literal, which it is not legal to change.
    // If you attempt to modify it on Linux you will get a runtime error.
    // Instead, you need to create an array to store the string in, e.g.:
    //
    // char str[] = "Hello!"
    // string_reverse(str)

    char str[] = ".'neetneves' :egassem terces A";
    string_reverse(str);
    printf("%s\n", str);
    return 0;
}

// Takes a string in `buffer`, and reverses it in-place.
void string_reverse(char *buffer) {
    int length = strlen(buffer);
    if (length != 0) {
        char str[length+1];
        int k = 0;
        for (int i = length-1; i >= 0; i--) {
            str[k] = buffer[i];
            k++;
        }
        str[length] = '\0';
        strcpy(buffer, str);
    }
}
