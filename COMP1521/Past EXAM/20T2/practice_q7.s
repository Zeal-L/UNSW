# Read numbers into an array until their sum is >= 42
# then print the numbers in reverse order

# i in register $t0
# registers $t1, $t2 & $t3 used to hold temporary results

main:
    li $t0, 0           # i = 0
    li $t4, 0           # i = 0
loop0:
    bge $t4, 42, end0 # while (i < 1000) {

    li $v0, 5           #   scanf("%d", &numbers[i]);
    syscall             #

    blt $v0, 0, end0    # if (x < 0) break
    mul $t1, $t0, 4     #   calculate &numbers[i]
    la  $t2, numbers    #
    add $t3, $t1, $t2   #
    sw  $v0, ($t3)      #   store entered number in array
    add $t4, $t4, $v0
    add $t0, $t0, 1     #   i++;
    b loop0             # }
end0:

loop1:
    ble $t0, 0, end1   # while (i > 0) {

    add $t0, $t0, -1    #   i--

    mul $t1, $t0, 4     #   calculate &numbers[i]
    la $t2, numbers     #
    add $t3, $t1, $t2   #
    lw $a0, ($t3)       #   load numbers[i] into $a0

    li $v0, 1           #   printf("%d", numbers[i])
    syscall

    li   $a0, '\n'      #   printf("%c", '\n');
    li   $v0, 11
    syscall

    b loop1             # }
end1:

    li $v0, 0           # return 0
    jr $31

.data
numbers:
    .space 4000