// // // // // // // // DO NOT CHANGE THIS FILE! // // // // // // // //
// COMP1521 21T2 ... final exam, question 1

#include <assert.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define BITS 8
#define BITS_STRLEN ((BITS) + 1)

void and (bool x[BITS], bool y[BITS], bool result[BITS]);
void or  (bool x[BITS], bool y[BITS], bool result[BITS]);
void xor (bool x[BITS], bool y[BITS], bool result[BITS]);
void not (bool x[BITS], bool result[BITS]);


typedef void (bitwise_unop_f)(bool x[BITS], bool out[BITS]);
typedef void (bitwise_binop_f)(bool x[BITS], bool y[BITS], bool out[BITS]);

static int do_and   (char *, char *);
static int do_or    (char *, char *);
static int do_xor   (char *, char *);
static int do_not   (char *);
static int do_unop  (char *, bitwise_unop_f *, char *);
static int do_binop (char *, char *, bitwise_binop_f *, char *);

static void zero_bit_array   (bool bit_array[BITS]);
static void str_to_bit_array (char str[BITS_STRLEN], bool bits[BITS]);
static void bit_array_to_str (bool bit_array[BITS], char str[BITS_STRLEN]);

#ifdef main
#undef main
#endif

int
main (int argc, char *argv[])
{
	if (argc == 4 && strcmp (argv[1], "-and") == 0) {
		return do_and (argv[2], argv[3]);

	} else if (argc == 4 && strcmp (argv[1], "-or") == 0) {
		return do_or (argv[2], argv[3]);

	} else if (argc == 4 && strcmp (argv[1], "-xor") == 0) {
		return do_xor (argv[2], argv[3]);

	} else if (argc == 3 && strcmp (argv[1], "-not") == 0) {
		return do_not (argv[2]);

	} else {
		return EXIT_FAILURE;
	}
}

static int
do_and (char *str_x, char *str_y)
{
	return do_binop (str_x, str_y, and, "&");
}

static int
do_or (char *str_x, char *str_y)
{
	return do_binop (str_x, str_y, or, "|");
}

static int
do_xor (char *str_x, char *str_y)
{
	return do_binop (str_x, str_y, xor, "^");
}

static int
do_not (char *str_x)
{
	return do_unop (str_x, not, "~");
}

static int
do_unop (char *str_x, bitwise_unop_f *op, char *name)
{
	assert (strlen (str_x) == BITS);

	bool bits_x[BITS] = { 0 };
	str_to_bit_array (str_x, bits_x);

	bool result[BITS];
	zero_bit_array (result);

	op (bits_x, result);

	char result_str[BITS_STRLEN];
	bit_array_to_str (result, result_str);
	printf (" %s%s\n  ========\n  %s\n\n", name, str_x, result_str);

	return EXIT_SUCCESS;
}

static int
do_binop (char *str_x, char *str_y, bitwise_binop_f *op, char *name)
{
	assert (strlen (str_x) == BITS);
	assert (strlen (str_y) == BITS);

	bool bits_x[BITS] = { 0 };
	str_to_bit_array (str_x, bits_x);

	bool bits_y[BITS] = { 0 };
	str_to_bit_array (str_y, bits_y);

	bool result[BITS];
	zero_bit_array (result);

	op (bits_x, bits_y, result);

	char result_str[BITS_STRLEN];
	bit_array_to_str (result, result_str);
	printf (
		"  %s %s\n  %s\n  ========\n  %s\n\n",
		str_x, name, str_y, result_str);

	return EXIT_SUCCESS;
}

static void
zero_bit_array (bool bit_array[BITS])
{
	for (int i = 0; i < BITS; i++) {
		bit_array[i] = 0;
	}
}

static void
str_to_bit_array (char str[BITS_STRLEN], bool bits[BITS])
{
	for (int i = 0; i < BITS; i++) {
		bits[i] = str[i] - '0';
	}
}

static void
bit_array_to_str (bool bit_array[BITS], char str[BITS_STRLEN])
{
	int i;

	for (i = 0; i < BITS; i++) {
		str[i] = bit_array[i] + '0';
	}

	str[i] = '\0';
}
