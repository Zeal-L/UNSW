# Read 10 numbers into an array
# print 0 if they are in non-decreasing order
# print 1 otherwise

# i in register $t0

main:

    li   $t0, 0         # i = 0
loop0:
    bge  $t0, 10, loop1b  # while (i < 10) {

    li   $v0, 5         #   scanf("%d", &numbers[i]);
    syscall             #

    mul  $t1, $t0, 4    #   calculate &numbers[i]
    la   $t2, numbers   #
    add  $t3, $t1, $t2  #
    sw   $v0, ($t3)     #   store entered number in array

    addi $t0, $t0, 1    #   i++;
    j    loop0          # }

loop1b:
    li   $t0, 1         # i = 0
    li   $t7, 4
    
loop1:

    bge  $t0, 10, nonDecreasing  # while (i < 10) {

    mul  $t1, $t0, 4    #   calculate &numbers[i]
    la   $t2, numbers   #
    add  $t3, $t1, $t2  #
    lw   $t6, ($t3)     #   load numbers[i] into $t6


    sub  $t4, $t3, $t7    # t4 = &last = curr - 4
    lw   $t5, ($t4)       # t5 = last
    blt  $t6, $t5, decreasing # curr < last goto decreasing

loop1a:
    addi $t0, $t0, 1    #   i++
    j    loop1          # }


decreasing:
    li   $a0, 1       # printf("%d", 1)
    li   $v0, 1         #
    syscall

    li   $a0, '\n'      # printf("%c", '\n');
    li   $v0, 11
    syscall

    jr   $ra

nonDecreasing:
    li   $a0, 0        # printf("%d", 0)
    li   $v0, 1         #
    syscall

    li   $a0, '\n'      # printf("%c", '\n');
    li   $v0, 11
    syscall

    jr   $ra


.data

numbers:
    .word 0 0 0 0 0 0 0 0 0 0  # int numbers[10] = {0};

