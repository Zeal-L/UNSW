# Read 10 numbers into an array
# then print the numbers which are
# larger than the last number read.

# i in register $t0
# registers $t1, $t2 & $t3 used to hold temporary results

main:
    li   $t0, 0         # i = 0

loop0:
    bge  $t0, 10, end0  # while (i < 10) {

    li   $v0, 5         #   scanf("%d", &numbers[i]);
    syscall             #

    mul  $t1, $t0, 4    #   calculate &numbers[i]
    la   $t2, numbers   #
    add  $t3, $t1, $t2  #
    sw   $v0, ($t3)     #   store entered number in array

    addi $t0, $t0, 1    #   i++;
    j    loop0          # }

end0:
    li   $t0, 0         # i = 0

loop1:
    bge  $t0, 10, end1  # while (i < 10) {

    mul  $t1, $t0, 4    #   calculate &numbers[i]
    la   $t2, numbers   #
    add  $t3, $t1, $t2  #
    lw   $a0, ($t3)     #   load numbers[i] into $a0

    ###
    addi $t4, $t2, 36     # t4 = last
    lw   $t5, ($t4)
    blt  $a0, $t5, loop1a # t3 < t4 goto loop1a
    ###

    li   $v0, 1         #   printf("%d", numbers[i])
    syscall

    li   $a0, '\n'      #   printf("%c", '\n');
    li   $v0, 11
    syscall

loop1a:
    addi $t0, $t0, 1    #   i++
    j    loop1          # }

end1:
    jr   $ra              # return


.data
numbers:
    .word 0 0 0 0 0 0 0 0 0 0  # int numbers[10] = {0};

