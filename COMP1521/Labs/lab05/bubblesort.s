# read 10 numbers into an array
# bubblesort them
# then print the 10 numbers

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
    li   $t0, 1         # swapped = 1

while1:
    li   $t8, 1
    bne	 $t0, $t8, whileEnd	# if $t0 != $t1 then target
    li   $t0, 0         # swapped = 0

swap:
    bge  $t8, 10, while1  # while (i < 10) {

    li   $t7, 4
    mul  $t1, $t8, 4    #   calculate &numbers[i]
    la   $t2, numbers   #
    add  $t3, $t1, $t2  #
    lw   $t6, ($t3)     #   load numbers[i] into $t6

    sub  $t4, $t3, $t7    # t4 = &last = curr - 4
    lw   $t5, ($t4)       # t5 = last
    blt  $t6, $t5, doSwap # curr < last goto decreasing

swapEnd:
    addi $t8, $t8, 1    #   i++
    j    swap          # }

doSwap:
    sw   $t5, ($t3)     #
    sw   $t6, ($t4)     #
    li   $t0, 1         # swapped = 1
    j    swapEnd

whileEnd:
    li   $t0, 0

loop1:
    bge  $t0, 10, end1  # while (i < 10) {

    mul  $t1, $t0, 4    #   calculate &numbers[i]
    la   $t2, numbers   #
    add  $t3, $t1, $t2  #
    lw   $a0, ($t3)     #   load numbers[i] into $a0
    li   $v0, 1         #   printf("%d", numbers[i])
    syscall

    li   $a0, '\n'      #   printf("%c", '\n');
    li   $v0, 11
    syscall

    addi $t0, $t0, 1    #   i++
    j    loop1          # }
end1:

    jr   $ra            # return

.data

numbers:
    .word 0 0 0 0 0 0 0 0 0 0  # int numbers[10] = {0};

