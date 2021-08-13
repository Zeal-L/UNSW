# COMP1521 20T3 final exam Q1 starter code

# This code reads 1 integer and prints it

# Change it to read 2 integers x and y,
# then print (x + y) * (x - y)

main:
    li   $v0, 5        #   scanf("%d", &x);
    syscall
    move $t0, $v0

    li   $v0, 5        #   scanf("%d", &x);
    syscall
    move $t1, $v0

    add $t2, $t0, $t1
    sub $t3, $t0, $t1

    mul $v0, $t2, $t3

    move $a0, $v0      #   printf("%d\n", x);
    li   $v0, 1
    syscall

    li   $a0, '\n'     #   printf("%c", '\n');
    li   $v0, 11
    syscall

end:
    li   $v0, 0        #   return 0;
    jr   $ra
