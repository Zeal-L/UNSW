#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>

int get_n_bit_set(uint8_t byte);

int main(int argc, char *argv[]) {

    FILE *fp = fopen(argv[1], "r");
    if (fp == NULL) {
        perror(argv[1]);
        return 1;
    }

    int total_num = 0;
    int byte = 0;
    while((byte = fgetc(fp)) != EOF) {
        total_num += get_n_bit_set(byte);
    }

    printf("%s has %d bits set\n",argv[1], total_num);

    fclose(fp);

    return 0;
}
int get_n_bit_set(uint8_t byte) {
    int bits_set = 0;
    for (int i = 0; i < 8; i++) {
        bits_set += byte & 0x1;
        byte >>=1;
    }
    return bits_set;
}