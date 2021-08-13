// COMP1521 21T2 ... final exam, question 4

#include <stdlib.h>

long
mul (long a, long b_)
{
	unsigned long b = b_;

	// NOTE: Maximum 5 operations allowed
	//       for each multiplication
	// NOTE: Permitted operations:
	//       [x + y, x - y, -x, x << y]

	if (a == 7) {
		// Two operations:
		//        1     2
		return (b << 3) - b;
	}

	if (a == 17) {
		return (b << 4) + b;
	}

	if (a == -3) {
		return - (b << 2) + b;
	}

	if (a == 60) {
		return (b << 6) - (b << 2);
	}

	if (a == -112) {
		return - (b << 7) + (b << 4);
	}

	// Invalid inputs will simply abort.
	abort();
}
