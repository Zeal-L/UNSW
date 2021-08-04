#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <assert.h>

int bcd(int bcd_value);

int main(int argc, char *argv[]) {

    for (int arg = 1; arg < argc; arg++) {
        long l = strtol(argv[arg], NULL, 0);
        assert(l >= 0 && l <= 0x0909);
        int bcd_value = l;

        printf("%d\n", bcd(bcd_value));
    }

    return 0;
}

// given a BCD encoded value between 0 .. 99
// return corresponding integer
int bcd(int bcd_value) {
    // 27对应的BCD码就是00000010 00000111
    return (bcd_value >> 8) * 10 + (bcd_value & 0xF);
}
