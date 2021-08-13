# this code reads 1 integer and prints it
# add code so that prints 1 iff
# the least significant (bottom) byte of the number read
# is equal to the 2nd least significant byte
# and it prints 0 otherwise

main:
    li   $v0, 5
    syscall

    andi $t0, $v0, 0xff
    srl  $t1, $v0, 8
    andi $t1, $t1, 0xff

    seq  $a0, $t0, $t1
    move $a0, $a0
    li   $v0, 1
    syscall

    li   $a0, '\n'
    li   $v0, 11
    syscall

end:
    li   $v0, 0
    jr   $31
