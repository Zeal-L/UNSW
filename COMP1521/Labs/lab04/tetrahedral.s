# Read a number n and print the first n tetrahedral numbers
# https://en.wikipedia.org/wiki/Tetrahedral_number

main:                     # int main(void) {
    la   $a0, prompt      # printf("Enter how many: ");
    li   $v0, 4
    syscall

    li   $v0, 5           # scanf("%d", how_many);
    syscall

    move $t0, $v0         # t0 = how_many
    li   $t1, 1           # t1 = n      = 1

    j loop1

loop1:
    bgt  $t1, $t0, end    # if (n > how_many) goto end;

    li   $t2, 0           # t2 = total  = 0
    li   $t3, 1           # t3 = j      = 1

    j    loop2

loop1b:
    move $a0, $t2         # printf("%d", total);
    li   $v0, 1
    syscall

    li   $a0, '\n'        # printf("%c", '\n');
    li   $v0, 11
    syscall

    addi $t1, $t1, 1      # n++;
    j    loop1

loop2:
    bgt  $t3, $t1, loop1b # if (j > n) goto end;
    li   $t4, 1           # t4 = i      = 1
    j    loop3

loop2b:
    addi $t3, $t3, 1      # j++;
    j    loop2

loop3:
    bgt  $t4, $t3, loop2b # if (i > j) goto end;
    add  $t2, $t2, $t4    # total = total + i;
    addi $t4, $t4, 1      # i++;
    j    loop3


end:
    jr   $ra              # return

    .data
prompt:
    .asciiz "Enter how many: "
