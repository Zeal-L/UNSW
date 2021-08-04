main:
    la   $a0, string0    # printf("Enter a number: ");
    li   $v0, 4
    syscall

    li   $v0, 5          # scanf("%d", x);
    syscall

    and  $t0, $v0, 1     # if (x & 1 == 0) {
    beq  $t0, 1, odd
or
    la   $a0, string1    # printf("Even\n");
    li   $v0, 4
    syscall

    j    end

odd:                     # else
    la   $a0, string2    # printf("Odd\n");
    li   $v0, 4
    syscall

end:
    li   $v0, 0          # return 0
    jr   $ra

    .data
string0:
    .asciiz "Enter a number: "
string1:
    .asciiz "Even\n"
string2:
    .asciiz "Odd\n"