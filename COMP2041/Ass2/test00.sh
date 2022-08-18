#! /bin/dash

compare() {
    if ! diff "$1" "$2"; then
        echo "test00-$3: FAILED" 1>&2
        exitCode=1
    fi
}

###########################
#  q - quit command Test  #
###########################

trap 'rm -fr $output $expected $tempDir ;exit' INT TERM EXIT

mySlippy="python3 -s -S $(pwd)/slippy"
cseSlippy="2041 slippy"
tempDir="$(mktemp -d)"
cd "$tempDir" || exit 1

exitCode=0


############################################################
# Test basic functionality of the slippy quit command
############################################################

expected=$(mktemp)
seq 1 5 | $cseSlippy '3q' > "$expected" 2>&1

output=$(mktemp)
seq 1 5 | $mySlippy '3q' > "$output" 2>&1

compare "$output" "$expected" 1


expected=$(mktemp)
seq 1 5 | $cseSlippy -n '3q' > "$expected" 2>&1

output=$(mktemp)
seq 1 5 | $mySlippy -n '3q' > "$output" 2>&1

compare "$output" "$expected" 1.2


############################################################
# Test slippy quit command with addrees argument
############################################################

expected=$(mktemp)
seq 10 15 | $cseSlippy '/.1/q' > "$expected" 2>&1

output=$(mktemp)
seq 10 15 | $mySlippy '/.1/q' > "$output" 2>&1

compare "$output" "$expected" 2


expected=$(mktemp)
seq 10 15 | $cseSlippy -n '/.1/q' > "$expected" 2>&1

output=$(mktemp)
seq 10 15 | $mySlippy -n '/.1/q' > "$output" 2>&1

compare "$output" "$expected" 2.1

############################################################
# Test slippy quit command with addrees argument
############################################################

expected=$(mktemp)
seq 500 600 | $cseSlippy '/^.+5$/q' > "$expected" 2>&1

output=$(mktemp)
seq 500 600 | $mySlippy '/^.+5$/q' > "$output" 2>&1

compare "$output" "$expected" 3


expected=$(mktemp)
seq 100 1000 | $cseSlippy '/1{3}/q' > "$expected" 2>&1

output=$(mktemp)
seq 100 1000 | $mySlippy '/1{3}/q' > "$output" 2>&1

compare "$output" "$expected" 4

############################################################
# Test slippy quit command with yes
############################################################

expected=$(mktemp)
yes | $cseSlippy '3q' > "$expected" 2>&1

output=$(mktemp)
yes | $mySlippy '3q' > "$output" 2>&1

compare "$output" "$expected" 5

############################################################
# Test slippy quit command with address /X/,X
############################################################

expected=$(mktemp)
seq 1 5 | $cseSlippy '/2/,5q' > "$expected" 2>&1

output=$(mktemp)
seq 1 5 | $mySlippy '/2/,5q' > "$output" 2>&1

compare "$output" "$expected" 6


expected=$(mktemp)
seq 1 5 | $cseSlippy -n '/2/,5q' > "$expected" 2>&1

output=$(mktemp)
seq 1 5 | $mySlippy -n '/2/,5q' > "$output" 2>&1

compare "$output" "$expected" 6.1


expected=$(mktemp)
seq 1 5 | $cseSlippy '/2/,$q' > "$expected" 2>&1

output=$(mktemp)
seq 1 5 | $mySlippy '/2/,$q' > "$output" 2>&1

compare "$output" "$expected" 7

############################################################
# Test slippy quit command with address X,/X/
############################################################

expected=$(mktemp)
seq 1 5 | $cseSlippy '2,/4/q' > "$expected" 2>&1

output=$(mktemp)
seq 1 5 | $mySlippy '2,/4/q' > "$output" 2>&1

compare "$output" "$expected" 8


expected=$(mktemp)
seq 1 5 | $cseSlippy -n '2,/4/q' > "$expected" 2>&1

output=$(mktemp)
seq 1 5 | $mySlippy -n '2,/4/q' > "$output" 2>&1

compare "$output" "$expected" 8.1


expected=$(mktemp)
seq 1 5 | $cseSlippy '$,/4/q' > "$expected" 2>&1

output=$(mktemp)
seq 1 5 | $mySlippy '$,/4/q' > "$output" 2>&1

compare "$output" "$expected" 9

############################################################
# Test slippy quit command with address X,X
############################################################

expected=$(mktemp)
seq 1 5 | $cseSlippy '3,5q' > "$expected" 2>&1

output=$(mktemp)
seq 1 5 | $mySlippy '3,5q' > "$output" 2>&1

compare "$output" "$expected" 10

expected=$(mktemp)
seq 1 5 | $cseSlippy -n '3,5q' > "$expected" 2>&1

output=$(mktemp)
seq 1 5 | $mySlippy -n '3,5q' > "$output" 2>&1

compare "$output" "$expected" 10.1


expected=$(mktemp)
seq 1 5 | $cseSlippy '$,5q' > "$expected" 2>&1

output=$(mktemp)
seq 1 5 | $mySlippy '$,5q' > "$output" 2>&1

compare "$output" "$expected" 11


expected=$(mktemp)
seq 1 5 | $cseSlippy '2,$q' > "$expected" 2>&1

output=$(mktemp)
seq 1 5 | $mySlippy '2,$q' > "$output" 2>&1

compare "$output" "$expected" 12

expected=$(mktemp)
seq 1 5 | $cseSlippy '$,$q' > "$expected" 2>&1

output=$(mktemp)
seq 1 5 | $mySlippy '$,$q' > "$output" 2>&1

compare "$output" "$expected" 13

expected=$(mktemp)
seq 1 5 | $cseSlippy '5,1q' > "$expected" 2>&1

output=$(mktemp)
seq 1 5 | $mySlippy '5,1q' > "$output" 2>&1

compare "$output" "$expected" 14

############################################################
# Test slippy quit command with address /X/,/X/
############################################################

expected=$(mktemp)
seq 1 100 | $cseSlippy '/44/,/66/q' > "$expected" 2>&1

output=$(mktemp)
seq 1 100 | $mySlippy '/44/,/66/q' > "$output" 2>&1

compare "$output" "$expected" 15


expected=$(mktemp)
seq 1 100 | $cseSlippy -n '/44/,/66/q' > "$expected" 2>&1

output=$(mktemp)
seq 1 100 | $mySlippy -n '/44/,/66/q' > "$output" 2>&1

compare "$output" "$expected" 15.1


expected=$(mktemp)
seq 1 100 | $cseSlippy '/44/,/-1/q' > "$expected" 2>&1

output=$(mktemp)
seq 1 100 | $mySlippy '/44/,/-1/q' > "$output" 2>&1

compare "$output" "$expected" 16

############################################################
# Exit with the correct exit code
############################################################

if [ $exitCode != 0 ]; then
    exit $exitCode
fi