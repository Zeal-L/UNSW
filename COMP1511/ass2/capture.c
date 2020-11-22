// capture.c
// Thomas Kunc (z5205060)
// 2020-03-10
// 1511 code to capture stdout.

#define _GNU_SOURCE
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include "capture.h"

// Store info about our writing to buf
struct cookie_cache {
    FILE *saved_stdout;
    char *buf;
    int bytes_written;
    int bytes_total;
};

// This gets called when we printf
ssize_t cookie_write(void *v, const char *buf, size_t size) {
    struct cookie_cache *cc = v;
    if (cc->bytes_written + size + 1 >= cc->bytes_total) {
      size = (cc->bytes_total - cc->bytes_written) - 1;
    }
    memcpy(cc->buf + cc->bytes_written, buf, size);
    cc->bytes_written += size;
    return size;
}

// This sets up the cookie_cache
struct cookie_cache *start_capture(char *buf, int size) {
    struct cookie_cache *cc = calloc(sizeof(struct cookie_cache), 1);
    cc->buf = buf;
    cc->bytes_written = 0;
    cc->bytes_total = size;
    cc->saved_stdout = stdout;

    stdout = fopencookie(cc, "w", (cookie_io_functions_t) {.write = cookie_write});
    return cc;
}

// And this takes it down
void end_capture(struct cookie_cache *cc) {
    fflush(stdout);
    fclose(stdout);
    stdout = cc->saved_stdout;
    cc->buf[cc->bytes_written] = '\0';
    free(cc);
}
