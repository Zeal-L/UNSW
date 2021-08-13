// COMP1521 21T2 ... final exam, question 9

#include <stdio.h>
#include <stdint.h>

int base64_init (void);
int base64_putbyte (uint8_t byte);
int base64_finish (void);

int main (void)
{
	base64_init ();

	int c;
	while ((c = getchar ()) != EOF) {
		base64_putbyte (c);
	}

	base64_finish();
	putchar('\n');

	return 0;
}


static uint8_t base64_lookup (uint8_t bits);
static uint16_t b64_buffer;
static uint32_t b64_bits;

int
base64_init (void)
{
	b64_buffer = 0;
	b64_bits   = 0;
	return 0;
}

static const uint8_t BASE64_LOOKUP[] =
	"ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	"abcdefghijklmnopqrstuvwxyz"
	"0123456789+/";

// Lookup the character for a given bit pattern.
static uint8_t
base64_lookup (uint8_t bits)
{
	return BASE64_LOOKUP[bits & 0x3f];
}

// Write a byte to a base64 stream.
int
base64_putbyte (uint8_t byte)
{
	b64_buffer = b64_buffer << 8;
	b64_buffer = b64_buffer  | byte;

	b64_bits = b64_bits + 8;

	while (b64_bits >= 6) {
		b64_bits = b64_bits - 6;
		uint8_t part = b64_buffer >> b64_bits;
		putchar (base64_lookup (part));
	}

	return 0;
}

// Write out any remaining data.
int
base64_finish (void)
{
	if (b64_bits > 0) {
		unsigned padding = 6 - b64_bits;
		b64_buffer = b64_buffer << padding;
		putchar (base64_lookup (b64_buffer));

		while (padding > 0) {
			putchar ('=');
			padding = padding - 2;
		}
	}

	b64_bits = 0;
	return 0;
}
