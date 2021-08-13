#include <stdio.h>

char *s;

int expression(void);
int term(void);
int number(void);

int main(int argc, char *argv[]) {
    char line[10000];
    fgets(line, 10000, stdin);
    s = line;
    printf("%d\n", expression());
    return 0;
}

int expression(void) {
    int left = term();
    if (*s != '+') {
        return left;
    }
    s++;
    int right = expression();
    return left + right;
}


int term(void) {
    int left = number();
    if (*s != '*') {
        return left;
    }
    s++;
    int right = term();
    return left * right;
}

int number(void) {
    int n = 0;
    while (*s >= '0' && *s <= '9') {
        n = 10 * n + *s - '0';
        s++;
    }
    return n;
}

