main:
    li		$t0, 42		    # $t0 = 42
    li		$t1, 0x10000000	# $t1 = 0x10000000
    # la      $t1, x
    sb		$t0, 0($t1)		# store 42 in address 0x10000000

    lb		$a0, 0($t1)		# load $a0 with the value I stored
    li		$v0, 1		    # $t1 = 1
    syscall

    li		$a0, '\n'		# $t1 = '\n'
    li      $v0, 11
    syscall

    li $v0, 0               # return 0
    jr $ra

.data
x:   .space 1

# 1521 spim -f