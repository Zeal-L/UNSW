#! /bin/dash

compare() {
    if ! diff "$1" "$2"; then
        echo "test04-$3: FAILED" 1>&2
        exitCode=1
    fi
}

#############################
#  s - substitute command   #
#############################

trap 'rm -fr $output $expected $tempDir ;exit' INT TERM EXIT

mySlippy="python3 -s -S $(pwd)/slippy"
cseSlippy="2041 slippy"
tempDir="$(mktemp -d)"
cd "$tempDir" || exit 1

exitCode=0


############################################################
# Test slippy substitute command with modifier character g
############################################################

expected=$(mktemp)
echo Hello Andrew | $cseSlippy 's/e//g' > "$expected" 2>&1

output=$(mktemp)
echo Hello Andrew | $mySlippy 's/e//g' > "$output" 2>&1

compare "$output" "$expected" 1


expected=$(mktemp)
seq 51 60 | $cseSlippy -n '5s/5/9/g' > "$expected" 2>&1

output=$(mktemp)
seq 51 60 | $mySlippy -n '5s/5/9/g' > "$output" 2>&1

compare "$output" "$expected" 2


############################################################
# Test slippy substitute command with non-whitespace delimiter 
############################################################

expected=$(mktemp)
seq 1 5 | $cseSlippy 'sX[15]XzzzX' > "$expected" 2>&1

output=$(mktemp)
seq 1 5 | $mySlippy 'sX[15]XzzzX' > "$output" 2>&1

compare "$output" "$expected" 3


expected=$(mktemp)
seq 1 5 | $cseSlippy -n 'sX[15]XzzzX' > "$expected" 2>&1

output=$(mktemp)
seq 1 5 | $mySlippy -n 'sX[15]XzzzX' > "$output" 2>&1

compare "$output" "$expected" 3.1


expected=$(mktemp)
seq 1 5 | $cseSlippy 's?[15]?zzz?' > "$expected" 2>&1

output=$(mktemp)
seq 1 5 | $mySlippy 's?[15]?zzz?' > "$output" 2>&1

compare "$output" "$expected" 4


expected=$(mktemp)
seq 1 5 | $cseSlippy 's_[15]_zzz_' > "$expected" 2>&1

output=$(mktemp)
seq 1 5 | $mySlippy 's_[15]_zzz_' > "$output" 2>&1

compare "$output" "$expected" 5


expected=$(mktemp)
seq 1 5 | $cseSlippy 'sX[15]Xz/z/zX' > "$expected" 2>&1

output=$(mktemp)
seq 1 5 | $mySlippy 'sX[15]Xz/z/zX' > "$output" 2>&1

compare "$output" "$expected" 6


expected=$(mktemp)
seq 1 5 | $cseSlippy 's;[15];z/z/z;' > "$expected" 2>&1

output=$(mktemp)
seq 1 5 | $mySlippy 's;[15];z/z/z;' > "$output" 2>&1

compare "$output" "$expected" 7


############################################################
# Exit with the correct exit code
############################################################

if [ $exitCode != 0 ]; then
    exit $exitCode
fi