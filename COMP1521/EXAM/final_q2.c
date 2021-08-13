// COMP1521 21T2 ... final exam, question 2

#include <stdint.h>
#include <stdio.h>

int
main (void)
{
	uint32_t n;
	scanf ("%d", &n);

	int bit_idx = 0;
	int n_bits_set = 0;

	while (bit_idx != 32) {
		int bit = (n >> bit_idx) & 1;
		n_bits_set = n_bits_set + bit;
		bit_idx++;
	}

	if (n_bits_set % 2 != 0) {
		printf ("the parity is odd\n");
	} else {
		printf ("the parity is even\n");
	}

	return 0;
}
