#include <stdio.h>
#include <stdlib.h>

void fail() {
    char n[10] = {0};
    scanf("%s", &n);
    printf("%sFAILLLLL\n", n);
}

void target() {
    printf("WINNNNNNN\n");
}

int main(int argc, char* argv[]) {

    setbuf(stdout, NULL);
    fail();
    return EXIT_SUCCESS;
}

