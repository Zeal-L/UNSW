// Zeal L (abc982210694@gmail.com)
// 2020-11-23 10:59:44
// Zid: z5325156
// 
// Display character arrays as text, by printing the individual
// characters -- a sample solution.

#include <assert.h>
#include <stdio.h>

#define ENOUGH_SPACE 100

void show_letters(int size, char letters[]);

int main(int argc, char *argv[]) {

    char letters_a[13] = {0};
    letters_a[0] = 72;
    letters_a[1] = 101;
    letters_a[2] = 108;
    letters_a[3] = 108;
    letters_a[4] = 111;
    letters_a[5] = 44;
    letters_a[6] = 32;
    letters_a[7] = 119;
    letters_a[8] = 111;
    letters_a[9] = 114;
    letters_a[10] = 108;
    letters_a[11] = 100;
    letters_a[12] = 33;
    show_letters(13, letters_a);

    putchar('\n');

    char letters_b[13] = {
        84,  101, 115, 116, 32,
        109, 101, 115, 115, 97,
        103, 101, 46
    };
    show_letters(13, letters_b);

    putchar('\n');

    char letters_c[11] = {
        's', 'a', 'm', 'p', 'l', 'e',
        ' ', 't', 'e', 'x', 't'
    };
    show_letters(11, letters_c);

    putchar('\n');

    char letters_d[ENOUGH_SPACE] = "a string";
    show_letters(8, letters_d);

    putchar('\n');

    return 0;
}

// print size characters from array letters
void show_letters(int size, char letters[]) {
    for (int i = 0; i < size; i++) {
        putchar(letters[i]);
    }
}
