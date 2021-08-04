# Sieve of Eratosthenes
# https://en.wikipedia.org/wiki/Sieve_of_Eratosthenes
main:
    li   $t0, 0             # $t0 = int i = 0;

while1:
    bge  $t0, 1000, mainA   # while (i < 1000) {
    mul  $t1, $t0, 2        #
    li   $t2, 1             #
    sb   $t2, prime($t1)    #   prime[i] = 1;
    addi $t0, $t0, 1        #   i++;
    j    while1             # }

mainA:
    li  $t0, 2              # $t0 = i = 2;

while2:
    bge $t0, 1000, end              # while (i < 1000) {
    lb  $t2, prime($t1)
    beq $t2, $zero, while2A         #   if (prime[i]) {

    move $a0, $t0                   #   printf("%d", i);
    li $v0, 1
    syscall
    li   $a0, '\n'                  #   printf("%c", '\n');
    li   $v0, 11
    syscall

    mul $t1, $t0, 2                 #   $t1 = int j = 2 * i;

while3:
    bge $t1, 1000, while2A          #   while (j < 1000) {
    sb  $zero, prime($t1)           #   prime[j] = 0;
    add $t1, $t1, $t0
    j   while3

while2A:
    addi $t0, $t0, 1                #   i++;
    j    while2


end:
    li $v0, 0           # return 0
    jr $31

.data
prime:
    .space 1000