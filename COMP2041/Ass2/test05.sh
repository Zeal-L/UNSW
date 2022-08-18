#! /bin/dash

compare() {
    if ! diff "$1" "$2"; then
        echo "test05-$3: FAILED" 1>&2
        exitCode=1
    fi
}

########################
#  Multiple Commands   #
########################

trap 'rm -fr $output $expected $tempDir ;exit' INT TERM EXIT

mySlippy="python3 -s -S $(pwd)/slippy"
cseSlippy="2041 slippy"
tempDir="$(mktemp -d)"
cd "$tempDir" || exit 1

exitCode=0


############################################################
# Test Multiple Commands Simple
############################################################

expected=$(mktemp)
seq 1 5 | $cseSlippy '4q;/2/d' > "$expected" 2>&1

output=$(mktemp)
seq 1 5 | $mySlippy '4q;/2/d' > "$output" 2>&1

compare "$output" "$expected" 1


expected=$(mktemp)
seq 1 5 | $cseSlippy '/2/d;4q' > "$expected" 2>&1

output=$(mktemp)
seq 1 5 | $mySlippy '/2/d;4q' > "$output" 2>&1

compare "$output" "$expected" 2


expected=$(mktemp)
seq 1 5 | $cseSlippy '/2/d;3p' > "$expected" 2>&1

output=$(mktemp)
seq 1 5 | $mySlippy '/2/d;3p' > "$output" 2>&1

compare "$output" "$expected" 3


expected=$(mktemp)
seq 1 5 | $cseSlippy 'p;/2/d;3p' > "$expected" 2>&1

output=$(mktemp)
seq 1 5 | $mySlippy 'p;/2/d;3p' > "$output" 2>&1

compare "$output" "$expected" 4


expected=$(mktemp)
seq 1 5 | $cseSlippy '/2/d;3s/./x/' > "$expected" 2>&1

output=$(mktemp)
seq 1 5 | $mySlippy '/2/d;3s/./x/' > "$output" 2>&1

compare "$output" "$expected" 5


############################################################
# Test Multiple Commands Complex
############################################################

expected=$(mktemp)
seq 1 5 | $cseSlippy 'p;p;/2/d;3s/./x/' > "$expected" 2>&1

output=$(mktemp)
seq 1 5 | $mySlippy 'p;p;/2/d;3s/./x/' > "$output" 2>&1

compare "$output" "$expected" 6


expected=$(mktemp)
seq 1 20 | $cseSlippy '/1/d;p;p;/2/d;3s/./x/;/../q' > "$expected" 2>&1

output=$(mktemp)
seq 1 20 | $mySlippy '/1/d;p;p;/2/d;3s/./x/;/../q' > "$output" 2>&1

compare "$output" "$expected" 7


expected=$(mktemp)
seq 1 20 | $cseSlippy -n '/1/d;p;/2/d;p;3s/./x/;/../q;/7/,1c xxx' > "$expected" 2>&1

output=$(mktemp)
seq 1 20 | $mySlippy -n '/1/d;p;/2/d;p;3s/./x/;/../q;/7/,1c xxx' > "$output" 2>&1

compare "$output" "$expected" 8


expected=$(mktemp)
seq 1 20 | $cseSlippy -n '/1/d;p;/2/d;p;3s/./x/;/../q;15d;/7/,/l/a xxx' > "$expected" 2>&1

output=$(mktemp)
seq 1 20 | $mySlippy -n '/1/d;p;/2/d;p;3s/./x/;/../q;15d;/7/,/l/a xxx' > "$output" 2>&1

compare "$output" "$expected" 9


############################################################
# Test Comments & White Space
############################################################

expected=$(mktemp)
seq 24 43 | $cseSlippy ' 3, 17  d  # comment' > "$expected" 2>&1

output=$(mktemp)
seq 24 43 | $mySlippy ' 3, 17  d  # comment' > "$output" 2>&1

compare "$output" "$expected" 10


expected=$(mktemp)
seq 24 43 | $cseSlippy '  /2/d # ## delete  ;; ;;  4  q ## ## quit' > "$expected" 2>&1

output=$(mktemp)
seq 24 43 | $mySlippy '  /2/d # ## delete  ;; ;;  4  q ## ## quit' > "$output" 2>&1

compare "$output" "$expected" 11


############################################################
# Exit with the correct exit code
############################################################

if [ $exitCode != 0 ]; then
    exit $exitCode
fi