// COMP1521 21T2 ... final exam, question 0

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

int
count_leading_zeroes (uint32_t x)
{
	int num = 32;
	uint32_t y = x >> 16;
	
	if (y != 0) {
		num -= 16;
		x = y;
	}
	y = x >> 8;

	if (y != 0) {
		num -= 8;
		x = y;
	}
	y = x >> 4;

	if (y != 0) {
		num -= 4;
		x = y;
	}
	y = x >> 2;

	if (y != 0) {
		num -= 2;
		x = y;
	}
	y = x >> 1;

	if (y == 0) {
		return num - x;
	} else {
		return num - 2;
	}
}

