# Read a number and print positive multiples of 7 or 11 < n

main:                  # int main(void) {
    la   $a0, prompt   # printf("Enter a number: ");
    li   $v0, 4
    syscall

    li   $v0, 5         # scanf("%d", number);
    syscall

    li   $t0, 1         # i = 1
    move $t3, $v0       # t3 = n

    j loop

loop:
    bge  $t0, $t3, end  # if (i >= n) goto end;

    rem  $t1, $t0, 7    # t1 = i % 7
    beqz $t1, print     # if (i % 7 == 0)

    rem  $t1, $t0, 11   # t1 = i % 11
    beqz $t1, print     # if (i % 11 == 0)

    addi $t0, $t0, 1    # i++;
    j    loop

print:
    move $a0, $t0       # printf("%d", i);
    li   $v0, 1
    syscall

    li   $a0, '\n'      # printf("%c", '\n');
    li   $v0, 11
    syscall

    addi $t0, $t0, 1    # i++;
    j    loop

end:
    jr   $ra            # return

    .data
prompt:
    .asciiz "Enter a number: "
