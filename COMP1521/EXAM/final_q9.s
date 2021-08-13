# COMP1521 21T2 ... final exam, question 9

	.text
main:
main__prologue:
        addiu   $sp, $sp, -4
        sw      $ra, ($sp)

main__body:
main__getc_cond:

	## v0 <- getchar
	jal	getchar

	## if (v0 < 0) goto main__getc_f
	bltz	$v0, main__getc_f

	## a0 <- v0
	move	$a0, $v0

	## putchar a0
	li	$v0, 11
	syscall

	j	main__getc_cond

main__getc_f:

main__epilogue:
        lw      $ra, ($sp)
        addiu   $sp, $sp, 4
	## return 0;
        li      $v0, 0
        jr      $ra



########################################################################
# .TEXT <getchar>
	.text
getchar:

	# This is a very simple `getchar(3)'-alike, because while
	# service call 12 should get a single character, it can't!
	#
	# (You may recognise this code from `snake.s'.)
	#
	# Arguments: none
	# Returns:   the byte read, or -1 if failed.
	# Frame:     none
	# Uses:      $a0, $a1, $v0
	# Clobbers:  $a0, $a1, $v0

        la	$a0, getchar_buf
        li	$a1, 2
        li	$v0, 8                  # syscall 8: read_string
        syscall

	.data
	.align	2
getchar_buf:
	.space	2

	.text
        lb	$v0, getchar_buf
	beq	$v0, 0, getchar__nul
	j	getchar__default

getchar__nul:
	li	$v0, -1
getchar__default:
	jr	$ra
