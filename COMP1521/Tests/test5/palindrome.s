# read a line and print whether it is a palindrom

main:
    la   $a0, str0       # printf("Enter a line of input: ");
    li   $v0, 4
    syscall

    la   $a0, line
    la   $a1, 256
    li   $v0, 8          # fgets(buffer, 256, stdin)
    syscall              #

    li   $t0, 0          # $t0 = int i = 0;

length:
    lb   $t1, line($t0)
    beq  $t1, $zero, mainA
    addi $t0, $t0, 1
    j    length

mainA:
    li   $t1, 0           # $t1 = int j = 0;
    addi $t2, $t0, -2     # $t2 = int k = i - 2;

while:
    bge  $t1, $t2, isP    # while (j < k) {

    lb   $t3, line($t1)
    lb   $t4, line($t2)
    bne  $t3, $t4, notP   # if (line[j] != line[k]) {

    addi $t1, $t1, 1      # j++;
    addi $t2, $t2, -1     # k--;
    j    while

notP:
    la   $a0, not_palindrome
    li   $v0, 4
    syscall

    li   $v0, 0          # return 0
    jr   $ra
isP:
    la   $a0, palindrome
    li   $v0, 4
    syscall

    li   $v0, 0          # return 0
    jr   $ra


.data
str0:
    .asciiz "Enter a line of input: "
palindrome:
    .asciiz "palindrome\n"
not_palindrome:
    .asciiz "not palindrome\n"


# line of input stored here
line:
    .space 256

