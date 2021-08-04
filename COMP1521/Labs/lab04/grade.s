# read a mark and print the corresponding UNSW grade

main:
    la   $a0, prompt    # printf("Enter a mark: ");
    li   $v0, 4
    syscall

    li   $v0, 5         # scanf("%d", mark);
    syscall
    bge  $v0, 85, hd_case
    bge  $v0, 75, dn_case
    bge  $v0, 65, cr_case
    bge  $v0, 50, ps_case
    j fl_case

end:
    li   $v0, 0         # return 0
    jr   $ra            # return


hd_case:
    la   $a0, hd        # printf("HD\n");
    li   $v0, 4
    syscall
    j    end

dn_case:
    la   $a0, dn        # printf("HD\n");
    li   $v0, 4
    syscall
    j    end
cr_case:
    la   $a0, cr        # printf("HD\n");
    li   $v0, 4
    syscall
    j    end
ps_case:
    la   $a0, ps        # printf("HD\n");
    li   $v0, 4
    syscall
    j    end
fl_case:
    la   $a0, fl        # printf("HD\n");
    li   $v0, 4
    syscall
    j    end


    .data
prompt:
    .asciiz "Enter a mark: "
fl:
    .asciiz "FL\n"
ps:
    .asciiz "PS\n"
cr:
    .asciiz "CR\n"
dn:
    .asciiz "DN\n"
hd:
    .asciiz "HD\n"
