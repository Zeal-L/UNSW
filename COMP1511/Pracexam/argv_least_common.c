#include <string.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>

int main(int argc, char* argv[]) {

    int count[100] = {0};
    for (int i = 1; i < argc; i++) {
        for (int j = 1; j < argc; j++) {
            if (strcmp(argv[i], argv[j]) == 0) {
                count[i]++;
            }
        }
    }
    int min = INT_MAX;
    int index = 1;
    for (int i = 1; i < 100; i++) {
        if (count[i] < min && count[i] != 0) {
            min = count[i];
            index = i;
        }
    }
    printf("%s", argv[index]);

    return EXIT_SUCCESS;
}

