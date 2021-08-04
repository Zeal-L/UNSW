#include <stdio.h>
#include <stdint.h>

void print_utf8_encoding(uint32_t code_point) {
    uint8_t encoding[5] = {0};

    if (code_point < 0x80) {
        encoding[0] = code_point;
    } else if (code_point < 0x800) {
        encoding[0] = 0xC0 | (code_point >> 6);
        encoding[1] = 0x80 | (code_point & 0x3f);
    } else if (code_point < 0x10000) {
        encoding[0] = 0xE0 | (code_point >> 12);
        encoding[1] = 0x80 | ((code_point >> 6) & 0x3f);
        encoding[2] = 0x80 | (code_point  & 0x3f);
    } else if (code_point < 0x200000) {
        encoding[0] = 0xF0 | (code_point >> 18);
        encoding[1] = 0x80 | ((code_point >> 12) & 0x3f);
        encoding[2] = 0x80 | ((code_point >> 6)  & 0x3f);
        encoding[3] = 0x80 | (code_point  & 0x3f);
    }

    printf("U+%x  UTF-8: ", code_point);
    for (uint8_t *s = encoding; *s != 0; s++) {
        printf("0x%02x ", *s);
    }
    printf(" %s\n", encoding);
}

int main(void) {
    print_utf8_encoding(0x42);
    print_utf8_encoding(0x00A2);
    print_utf8_encoding(0x10be);
    print_utf8_encoding(0x1F600);
    print_utf8_encoding(0x4e80);
}