// COMP1521 21T2 ... final exam, question 6

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <ctype.h>
#include <string.h>
int HexToDec(char* str)
{
    int i = 0, num, result = 0;
    while (str[i] && str[i] != '\n') {
        result <<= 4;
        if (str[i] >= 'a')
            num = str[i] - 'a' + 10;
        else
            num = str[i] - '0';
        result += num;
        i++;
    }
    return result;
}

void convert_hexdump_to_bytes (FILE *hexdump_input, FILE *byte_output) {
	unsigned int all[BUFSIZ][16];
	for (int i = 0; i < BUFSIZ; i++) {
		for (int j = 0; j < 16; j++) {
			all[i][j] = 0;
		}
	}
	unsigned int line[BUFSIZ] = {0};

	int total_line = 0;
	while (1) {
		char linenum[BUFSIZ] = {0};
		if (fscanf(hexdump_input, "%s", linenum) == EOF) break;
		//printf("%d\n", HexToDec(linenum)/16);
		for (int j = 0; j < 16; j++) {
			fscanf(hexdump_input, "%x", line);
			all[HexToDec(linenum)/16][j] = line[0];
		}
		total_line++;
		for (int i = 0; i < 20; i++) fgetc(hexdump_input);
	}

	for (int j = 0; j < total_line; j++) {
		for (int i = 0; i < 16; i++) {
			fprintf(byte_output, "%c", all[j][i]);
		}
	}
}
