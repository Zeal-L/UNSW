# add 17 and 25 using variables stored in memory and print result

main:
    la   $t0, x
    lw   $t1, 0($t0)
    la   $t0, y
    lw   $t2, 0($t0)
    add  $t3, $t1, $t2 # z = x + y
    la   $t0, z
    sw   $t3, 0($t0)

    la   $t0, z
    lw   $a0, 0($t0)
    li   $v0, 1       # printf("%d", z);
    syscall

    li   $a0, '\n'    # printf("%c", '\n');
    li   $v0, 11
    syscall

    li   $v0, 0       # return 0
    jr   $ra

.data
x:  .word 17
y:  .word 25
z:  .space 4