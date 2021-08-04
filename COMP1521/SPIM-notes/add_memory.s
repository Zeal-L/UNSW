main:
    li   $t0, 17       # x = 17;
    la   $t1, x
    sw   $t0, 0($t1)

    li   $t0, 25       # y = 25;
    la   $t1, y
    sw   $t0, 0($t1)

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
x:  .space 4
y:  .space 4
z:  .space 4