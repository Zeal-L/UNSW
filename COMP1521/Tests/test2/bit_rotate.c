#include "bit_rotate.h"

// return the value bits rotated left n_rotations
uint16_t bit_rotate(int n_rotations, uint16_t bits) {

    // if (n_rotations < 0) {
    //     int n = n_rotations % 16 + 16;
    //     uint16_t result = (bits << n) | (bits >> (16 - n));
    //     return result;
    // } else {
    //     int n = n_rotations % 16;
    //     uint16_t result = (bits << n) | (bits >> (16 - n));
    //     return result;
    // }


    return n_rotations < 0
        ? (bits << (16 + n_rotations % 16)) | (bits >> (-n_rotations % 16))
        : (bits >> (16 - n_rotations % 16)) | (bits << ( n_rotations % 16));
}
