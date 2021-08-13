#include <stdio.h>
#include <stdlib.h>



int main(int argc, char *argv[]) {

    int n = atoi(argv[1]);
    FILE *fp = fopen(argv[2], "r");
    if (fp == NULL) {
        perror(argv[2]);
        return 1;
    }
    FILE *new_fp = fopen(argv[3], "w");
    if (new_fp == NULL) {
        perror(argv[3]);
        return 1;
    }

    int total_num = 0;
    while(fgetc(fp) != EOF) total_num++;

    fseek(fp, 0, SEEK_SET);

    if (total_num <= n) return 1;

    for (int i = 0; i < total_num - n; i++) {
        fputc(fgetc(fp), new_fp);
    }

    fclose(fp);
    fclose(new_fp);
    return 0;
}