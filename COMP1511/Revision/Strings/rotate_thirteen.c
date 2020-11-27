// Zeal L (abc982210694@gmail.com)
// 2020-11-23 12:33:12
// Zid: z5325156
// 
// Perform the ROT13 algorithm on a string


#include <assert.h>
#include <stdio.h>
#include <stdlib.h>

#define MAX_LENGTH 256

// Add your own #defines here

void rotate_thirteen(char *string);
char rotate_one(char c);
void rotate_thirteen(char *string);
int strings_equal(char *string1, char *string2);

// Add your own function prototypes here

int main(int argc, char *argv[]) {
    // Example tests
    char test_a[MAX_LENGTH] = "Hello, world!";
    rotate_thirteen(test_a);
    assert(strings_equal("Uryyb, jbeyq!", test_a));

    char test_b[MAX_LENGTH] = "abcdefghijklmnopqrstuvwxyz";
    rotate_thirteen(test_b);
    assert(strings_equal("nopqrstuvwxyzabcdefghijklm", test_b));

    char test_c[MAX_LENGTH] = "The quick brown fox jumped over the lazy dog.";
    rotate_thirteen(test_c);
    assert(strings_equal("Gur dhvpx oebja sbk whzcrq bire gur ynml qbt.", test_c));

    // Add your own tests here

    printf("All tests passed. You are awesome!\n");

    return 0;
}

void rotate_thirteen(char *string) {
    for (int i = 0; string[i] != '\0'; i++) {
        for (int j = 0; j < 13; j++) {
            string[i] = rotate_one(string[i]);
        }
    }
    
}

char rotate_one(char c) {
    if ((c >= 97 && c <= 122) || (c >= 65 && c <= 90)) {
        if ((c == 122) || (c == 90)) {
            return c-25;
        }
        return c+1;
    }
    return c;
}

int strings_equal(char *string1, char *string2) {
    int counter1 = 0;
    while (string1[counter1] != '\0') {
        counter1++;
    }
    int counter2 = 0;
    while (string2[counter2] != '\0') {
        counter2++;
    }
    if (counter1 != counter2) {
        return 0;
    }

    for (int i = 0; string1[i] != '\0'; i++) {
        if (string1[i] != string2[i]) {
            return 0;
        }
    }
    return 1;
}
