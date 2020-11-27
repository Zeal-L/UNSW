// Zeal L (abc982210694@gmail.com)
// 2020-11-23 11:06:39
// Zid: z5325156
// 
// String Equality


#include <stdio.h>
#include <assert.h>

int strings_equal(char *string1, char *string2);

int main(int argc, char *argv[]) {

    // Some simple assert-based tests.
    // You probably want to write some more.
    assert(strings_equal("", "") == 1);
    assert(strings_equal(" ", "") == 0);
    assert(strings_equal("", " ") == 0);
    assert(strings_equal(" ", " ") == 1);
    assert(strings_equal("\n", "\n") == 1);
    assert(strings_equal("This is 17 bytes.", "") == 0);
    assert(strings_equal("", "This is 17 bytes.") == 0);
    assert(strings_equal("This is 17 bytes.", "This is 17 bytes.") == 1);
    assert(strings_equal("Here are 18 bytes!", "This is 17 bytes.") == 0);

    printf("All tests passed.  You are awesome!\n");

    return 0;
}


// Takes two strings, and if they are the same,
// returns 1, or 0 otherwise.
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
