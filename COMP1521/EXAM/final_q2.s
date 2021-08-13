# COMP1521 21T2 ... final exam, question 2

	.data
even_parity_str:	.asciiz "the parity is even\n"
odd_parity_str:		.asciiz "the parity is odd\n"

	.text
main:
	li	$v0, 5
	syscall
	move	$t0, $v0
	# input is in $t0

	li $t1, 0	# $t1 = int bit_idx = 0;
	li $t2, 0	# $t2 = int n_bits_set = 0;

while:

	beq	$t1, 32, while_end
	srav $t3, $t0, $t1
	andi $t4, $t3, 1	# $t4 = int bit = (n >> bit_idx) & 1;
	add $t2, $t2, $t4	# n_bits_set = n_bits_set + bit;
	addi $t1, $t1, 1
	j 	while

while_end:
	remu $t5, $t2, 2
	bne $t5, 0, odd_end


even_end:
	li	$v0, 4
	la	$a0, even_parity_str
	syscall

	li	$v0, 0
	jr	$ra

odd_end:
	li	$v0, 4
	la	$a0, odd_parity_str
	syscall

	li	$v0, 0
	jr	$ra
