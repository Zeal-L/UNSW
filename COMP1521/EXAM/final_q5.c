// COMP1521 21T2 ... final exam, question 5

#include <sys/types.h>

#include <sys/stat.h>
#include <sys/wait.h>

#include <assert.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

// [[ TODO: put any extra `#include's here ]]

#include <glob.h>
#include <spawn.h>
#include <math.h>

void
print_utf8_count (FILE *file) {
	unsigned long amount_1_byte = 0;
	unsigned long amount_2_byte = 0;
	unsigned long amount_3_byte = 0;
	unsigned long amount_4_byte = 0;

	int i = fgetc(file);
	while(!feof(file)){
		if((i & 0x80) == 0x00) amount_1_byte++;
		if((i & 0xE0) == 0xC0) amount_2_byte++;
		if((i & 0xF0) == 0xE0) amount_3_byte++;
		if((i & 0xF8) == 0xF0) amount_4_byte++;
		i = fgetc(file);
	}

	printf("1-byte UTF-8 characters: %lu\n", amount_1_byte);
	printf("2-byte UTF-8 characters: %lu\n", amount_2_byte);
	printf("3-byte UTF-8 characters: %lu\n", amount_3_byte);
	printf("4-byte UTF-8 characters: %lu\n", amount_4_byte);
}