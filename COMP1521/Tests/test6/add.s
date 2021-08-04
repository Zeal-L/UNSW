	.data
main__usage_1: 	.asciiz "Usage: 1521 spim -f "
main__usage_2: 	.asciiz " <d> <s> <t>\n"
main__add_1:	.asciiz "make_add("
main__add_2:	.asciiz ", "
main__add_3:	.asciiz ") returned "

	.text
make_add:
	# Args:
	# - uint32_t d in $a0
	# - uint32_t s in $a1
	# - uint32_t t in $a2

	sll $a0, $a0, 11
	sll $a1, $a1, 21
	sll $a2, $a2, 16
	or  $v0, $a1, $a0
	or  $v0, $a2, $v0
	li  $t0, 32
	or  $v0, $t0, $v0

	jr	$ra



##################################################
#                                                #
#                DO NOT CHANGE CODE              #
#                 BELOW THIS POINT               #
#                                                #
##################################################


main:
main__prologue:
	addiu	$sp, $sp, -16
	sw	$ra, 12($sp)
	sw	$s0,  8($sp)
	sw	$s1,  4($sp)
	sw	$s2,   ($sp)

main__body:
	beq	$a0, 4, main__argc_ok
	li	$v0, 4
	la	$a0, main__usage_1
	syscall

	li	$v0, 4
	lw	$a0, ($a1)
	syscall

	li	$v0, 4
	la	$a0, main__usage_2
	syscall

	la	$v0, 1
	b	main__epilogue

main__argc_ok:
	lw	$a0, 4($a1)
	jal	strtod
	move	$s0, $v0

	lw	$a0, 8($a1)
	jal	strtod
	move	$s1, $v0

	lw	$a0, 12($a1)
	jal	strtod
	move	$s2, $v0

	move	$a0, $s0
	move	$a1, $s1
	move	$a2, $s2
	jal	make_add
	move	$t0, $v0

	li	$v0, 4
	la	$a0, main__add_1
	syscall

	li	$v0, 1
	move	$a0, $s0
	syscall

	li	$v0, 4
	la	$a0, main__add_2
	syscall

	li	$v0, 1
	move	$a0, $s1
	syscall

	li	$v0, 4
	la	$a0, main__add_2
	syscall

	li	$v0, 1
	move	$a0, $s2
	syscall

	li	$v0, 4
	la	$a0, main__add_3
	syscall

	li	$v0, 1
	move	$a0, $t0
	syscall

	li	$v0, 11
	li	$a0, '\n'
	syscall

	li	$v0, 0

main__epilogue:
	lw	$s2,   ($sp)
	lw	$s1,  4($sp)
	lw	$s0,  8($sp)
	lw	$ra, 12($sp)
	addiu	$sp, $sp, 16

	jr	$ra



strtod:
	li	$t0, 0

strtod__loop:
	lb	$t1, ($a0)
	beqz	$t1, strtod__break
	mul	$t0, $t0, 10
	sub	$t1, $t1, '0'
	add	$t0, $t0, $t1
	addiu	$a0, $a0, 1
	b	strtod__loop

strtod__break:
	move	$v0, $t0
	jr	$ra

