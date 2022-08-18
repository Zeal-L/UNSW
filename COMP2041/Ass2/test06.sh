#! /bin/dash

compare() {
    if ! diff "$1" "$2"; then
        echo "test06-$3: FAILED" 1>&2
        exitCode=1
    fi
}

trap 'rm -fr $output $expected $tempDir ;exit' INT TERM EXIT

mySlippy="python3 -s -S $(pwd)/slippy"
cseSlippy="2041 slippy"
tempDir="$(mktemp -d)"
cd "$tempDir" || exit 1

exitCode=0


############################################################
# Test -f command line option simple
############################################################

echo 4q   >  commands.slippy
echo /2/d >> commands.slippy

expected=$(mktemp)
seq 1 5 | $cseSlippy -f commands.slippy > "$expected" 2>&1

output=$(mktemp)
seq 1 5 | $mySlippy -f commands.slippy > "$output" 2>&1

compare "$output" "$expected" 1


echo /2/d >  commands.slippy
echo 4q   >> commands.slippy

expected=$(mktemp)
seq 1 5 | $cseSlippy -f commands.slippy > "$expected" 2>&1

output=$(mktemp)
seq 1 5 | $mySlippy -f commands.slippy > "$output" 2>&1

compare "$output" "$expected" 2


echo 'p;p;/2/d;3s/./x/' >  commands.slippy

expected=$(mktemp)
seq 1 5 | $cseSlippy -f commands.slippy > "$expected" 2>&1

output=$(mktemp)
seq 1 5 | $mySlippy -f commands.slippy > "$output" 2>&1

compare "$output" "$expected" 3


echo '/1/d;p;/2/d;'       >  commands.slippy
echo 'p;3s/./x/;/../q;'   >> commands.slippy
echo '15d;/7/,/l/a xxx'   >> commands.slippy

expected=$(mktemp)
seq 1 5 | $cseSlippy -f commands.slippy > "$expected" 2>&1

output=$(mktemp)
seq 1 5 | $mySlippy -f commands.slippy > "$output" 2>&1

compare "$output" "$expected" 4


############################################################
# Test slippy with Input Files
############################################################

seq 1 10 > two.txt
seq 1 5 > five.txt

expected=$(mktemp)
$cseSlippy '4q;/2/d' two.txt five.txt > "$expected" 2>&1

output=$(mktemp)
$mySlippy '4q;/2/d' two.txt five.txt > "$output" 2>&1

compare "$output" "$expected" 5


seq 1 10 > ten.txt
seq 1 5 > five.txt

expected=$(mktemp)
$cseSlippy '4q;/2/d' ten.txt five.txt > "$expected" 2>&1

output=$(mktemp)
$mySlippy '4q;/2/d' ten.txt five.txt > "$output" 2>&1

compare "$output" "$expected" 6


seq 1 10 > ten.txt
seq 1 5 > five.txt

expected=$(mktemp)
$cseSlippy 'sX[15]XzzzX;p' five.txt ten.txt > "$expected" 2>&1

output=$(mktemp)
$mySlippy 'sX[15]XzzzX;p' five.txt ten.txt > "$output" 2>&1

compare "$output" "$expected" 7


############################################################
# Test Combine -f and Input Files
############################################################

echo 8q   >  commands.slippy
echo /2/,5d >> commands.slippy
seq 1 10 > ten.txt
seq 1 5 > five.txt

expected=$(mktemp)
$cseSlippy -f commands.slippy ten.txt five.txt > "$expected" 2>&1

output=$(mktemp)
$mySlippy -f commands.slippy ten.txt five.txt > "$output" 2>&1

compare "$output" "$expected" 8


echo 'sX[15]XzzzX;'   >  commands.slippy
echo '/1/d;p;p;/2/d;3s/./x/;/9./q' >> commands.slippy
seq 1 10 > ten.txt
seq 1 100 > hundred.txt

expected=$(mktemp)
$cseSlippy -n -f -n commands.slippy ten.txt hundred.txt > "$expected" 2>&1

output=$(mktemp)
$mySlippy -n -f -n commands.slippy ten.txt hundred.txt > "$output" 2>&1


compare "$output" "$expected" 9


############################################################
# Test slippy with -i command line option
############################################################

seq 1 10 > ten.txt

expected=$(mktemp)
$cseSlippy -i /[246]/d ten.txt 
cat ten.txt > "$expected" 2>&1

seq 1 10 > ten.txt

output=$(mktemp)
$mySlippy -i /[246]/d ten.txt 
cat ten.txt > "$output" 2>&1

compare "$output" "$expected" 10


seq 1 100 > hundred.txt

expected=$(mktemp)
$cseSlippy -i '/[246]/d;/44/,$a xxx' hundred.txt 
cat hundred.txt > "$expected" 2>&1

seq 1 100 > hundred.txt

output=$(mktemp)
$mySlippy -i '/[246]/d;/44/,$a xxx' hundred.txt 
cat hundred.txt > "$output" 2>&1

compare "$output" "$expected" 11


############################################################
# Exit with the correct exit code
############################################################

if [ $exitCode != 0 ]; then
    exit $exitCode
fi