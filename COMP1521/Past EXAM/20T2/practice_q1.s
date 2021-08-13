#  print the sum of two integers
# x in $t0, y in $t1
main:
    li $v0, 5           #   scanf("%d", &x);
    syscall             #
    move $t0, $v0

    li $v0, 5           #   scanf("%d", &y);
    syscall             #
    move $t1, $v0


    add $a0, $t0, $t1   #   z = x + y
    li $v0, 1           #   printf("%d", z);
    syscall

    li   $a0, '\n'      #   printf("%c", '\n');
    li   $v0, 11
    syscall

end:

    li $v0, 0           # return 0
    jr $31