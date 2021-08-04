# calculate 1*1 + 2*2 + ... + 99 * 99 + 100 * 100

# sum in $t0, i in $t1, square in $t2

main:
    li   $t0, 0         # sum = 0;
    li   $t1, 0         # i = 0

loop:
    bgt  $t1, 100, end  # if (i > 100) goto end;
    mul  $t2, $t1, $t1  # square = i * i;
    add  $t0, $t0, $t2  # sum = sum + square;
    
    move $a0, $t1 # print i
    li $v0, 1
    syscall

    li $a0, ' '
    li $v0, 11
    syscall

    move $a0, $t0 # print sum
    li $v0, 1
    syscall

    li $a0, '\n'
    li $v0, 11
    syscall


    addi $t1, $t1, 1    # i = i + 1;
    j    loop

end:
    move $a0, $t0       # printf("%d", sum);
    li   $v0, 1
    syscall

    li   $a0, '\n'      # printf("%c", '\n');
    li   $v0, 11
    syscall

    li   $v0, 0         # return 0
    jr   $ra