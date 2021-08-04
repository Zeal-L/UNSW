// 6 ways to print Hello, stdio!

#include <stdio.h>

int main(void) {
    char bytes[] = "Hello, stdio!\n"; // 15 bytes

    // write 14 bytes so we don't write (terminating) 0 byte
    for (int i = 0; i < (sizeof bytes) - 1; i++) {
        fputc(bytes[i], stdout);
    }

    // or as we know bytes is 0-terminated
    for (int i = 0; bytes[i] != '\0'; i++) {
        fputc(bytes[i], stdout);
    }

    // or if you prefer pointers
    for (char *p = &bytes[0]; *p != '\0'; p++) {
        fputc(*p, stdout);
    }

    // fputs relies on bytes being 0-terminated
    fputs(bytes, stdout);

    // write 14 1 byte items
    fwrite(bytes, 1, (sizeof bytes) - 1, stdout);

    // %s relies on bytes being 0-terminated
    fprintf(stdout, "%s", bytes);

    return 0;
}