main:
    li   $s0, 0
    la   $a0, msg1
    li   $v0, 4
    syscall            # printf(Enter n: ")

    li    $v0, 5
    syscall            # scanf("%d", &n)
    move $t0, $v0      # $t0 = n

    j     factorial    #

factorial:
    li $t1, 1           # $t1 = int len = 1;
    sh $t1, a($zero)    # a[0] = 1;

    li $t2, 2           # $t2 = int i = 2

for1:
    bgt $t2, $t0, print # for (int i = 2; i <= n; i++) {
    li  $t3, 0          # $t3 = int carry = 0;

    li  $t4, 0          # $t4 = int j = 0

for2:
    bge $t4, $t1, for1a  # for (int j = 0; j < len; j++) {

    mul $t6, $t4, 2
    lh  $t5, a($t6)
    mul $t5, $t5, $t2
    add $t5, $t5, $t3    # $t5 = int temp = a[j] * i + carry;

    rem $t7, $t5, 10
    sh  $t7, a($t6)     # a[j] = temp % 10;

    div $t3, $t5, 10    # carry = temp / 10;

    addi $t6, $t1, -1
    bge  $t4, $t6, if
    j    for2a

if:
    bgt $t3, $zero, if2
    j   for2a
if2:
    addi $t1, $t1, 1

for2a:
    addi $t4, $t4, 1
    j   for2

for1a:
    addi $t2, $t2, 1
    j   for1

print:
    move  $a0, $t0
    li    $v0, 1
    syscall            # printf ("%d", n)

    la    $a0, msg2
    li    $v0, 4
    syscall            # printf("! = ")

    addi $t3, $t1, -1

while:
    blt $t3, $zero, printA  # for (int i = len-1; i >= 0; i--) {

    mul $t2, $t3, 2
    lh  $a0, a($t2)
    li    $v0, 1
    syscall            # printf("%d",a[i]);

    addi $t3, $t3, -1
    j while

printA:
    li   $a0, '\n'     # printf("%c", '\n');
    li   $v0, 11
    syscall


    li  $v0, 0         # return 0
    jr  $ra

    .data
msg1:   .asciiz "Enter n: "
msg2:   .asciiz "! = "

a:
    .align 2
    .space 20000

