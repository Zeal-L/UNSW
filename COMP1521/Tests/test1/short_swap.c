// Swap bytes of a short

#include <stdint.h>
#include <stdlib.h>
#include <assert.h>

// given uint16_t value return the value with its bytes swapped
uint16_t short_swap(uint16_t value) {

    return ((value & 0x00ff) << 8) | ((value & 0xff00) >> 8);
}
