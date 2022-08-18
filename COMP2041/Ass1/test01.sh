#! /bin/dash

######################
#  tigger-add Test   #
######################

trap 'rm -fr $output $expected $my $cse;exit' INT TERM EXIT

tigger=$(pwd)
my="$(mktemp -d)"
cse="$(mktemp -d)"


############################################################
# Test tigger-add: error: tigger repository directory .tigger not found
############################################################

cd "$my" || exit 1
output=$(mktemp)
"$tigger"/tigger-add output > "$output" 2>&1

cd "$cse" || exit 1
expected=$(mktemp)
2041 tigger-add expected > "$expected" 2>&1

if ! diff "$output" "$expected"; then
    echo "test01-1: FAILED" 1>&2
    exit 1
fi

############################################################
# Initializa empty tigger repository in .tigger
############################################################

cd "$my" || exit 1
"$tigger"/tigger-init 1>/dev/null

cd "$cse" || exit 1
2041 tigger-init 1>/dev/null

############################################################
# Test invalid number of arguments
# usage: tigger-add <filenames>
############################################################

cd "$my" || exit 1
output=$(mktemp)
"$tigger"/tigger-add > "$output" 2>&1

cd "$cse" || exit 1
expected=$(mktemp)
2041 tigger-add > "$expected" 2>&1

if ! diff "$output" "$expected"; then
    echo "test01-2: FAILED" 1>&2
    exit 1
fi

############################################################
# Test tigger-add: error: invalid filename '$file'
############################################################

cd "$my" || exit 1
output=$(mktemp)
"$tigger"/tigger-add "//" > "$output" 2>&1

cd "$cse" || exit 1
expected=$(mktemp)
2041 tigger-add "//" > "$expected" 2>&1

if ! diff "$output" "$expected"; then
    echo "test01-3: FAILED" 1>&2
    exit 1
fi

############################################################
# Test tigger-add: error: can not open '$file'
############################################################

cd "$my" || exit 1
output=$(mktemp)
"$tigger"/tigger-add xxx > "$output" 2>&1

cd "$cse" || exit 1
expected=$(mktemp)
2041 tigger-add xxx > "$expected" 2>&1

if ! diff "$output" "$expected"; then
    echo "test01-4: FAILED" 1>&2
    exit 1
fi

echo "test01: ALL PASS" 1>&2

