// copy stdin to stdout implemented with fwrite

#include <stdio.h>

int main(void) {
    while (1) {
        char bytes[4096];

        ssize_t bytes_read = fread(bytes, 1, sizeof bytes, stdin);

        if (bytes_read <= 0) {
            break;
        }

        fwrite(bytes, 1, bytes_read, stdout);
    }

    return 0;
}