# this code reads a line of input and prints 42
# change it to evaluate the arithmetic expression

main:
    la   $a0, line
    la   $a1, 10000
    li   $v0, 8          # fgets(buffer, 256, stdin)
    syscall              #



    li   $a0, 42         # printf("%d", 42);
    li   $v0, 1
    syscall

    li   $a0, '\n'       # printf("%c", '\n');
    li   $v0, 11
    syscall

    li   $v0, 0          # return 0
    jr   $31


.data
line:
    .space 10000

