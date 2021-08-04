#include "sign_flip.h"

// given the 32 bits of a float return it with its sign flipped
uint32_t sign_flip(uint32_t f) {

    return (((f >> 31) ? (uint32_t) 0 : (uint32_t) 1) << 31) | (f << 1) >> 1;
}
