main:
    # ... pass address of string as argume
    la $a0, string
    # ... 4 is printf ”%s” syscall number
    li $v0, 4
    syscall

    li $v0, 0   # return 0
    jr $ra

    .data
string:
    .asciiz "I MIPS you!\n"


# 1521 spim -f
