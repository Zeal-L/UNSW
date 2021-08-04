main:
    li   $v0, 5         #   scanf("%d", &x);
    syscall             #
    move $t0, $v0

    li   $v0, 5         #   scanf("%d", &y);
    syscall             #
    move $t1, $v0

    addi  $t2, $t0, 1   # i = x + 1
    li    $t3, 13
loop:
    bge   $t2, $t1, end
    bne   $t2, $t3, print

loopb:
    addi  $t2, $t2, 1
    j     loop

print:
    move   $a0, $t2     #   printf("%d\n", i);
    li   $v0, 1
    syscall
    li   $a0, '\n'      #   printf("%c", '\n');
    li   $v0, 11
    syscall
    j    loopb

end:
    li   $v0, 0         # return 0
    jr   $ra
