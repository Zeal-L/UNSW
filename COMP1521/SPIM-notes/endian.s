main:
    li   $t0, 0x03040506
    la   $t1, u
    sw   $t0, 0($t1) # u = 0x03040506;
                     # 0 = 06, 1 = 05 ...
    lb   $a0, 0($t1) # b = *(uint8_t *)&u;

    li   $v0, 1      # printf("%d", a0);

    syscall

    li   $a0, '\n'   # printf("%c", '\n');
    li   $v0, 11
    syscall


    li   $v0, 0     # return 0
    jr   $ra

    .data
u:
    .space 4