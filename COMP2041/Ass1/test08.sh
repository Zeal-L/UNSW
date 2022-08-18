#! /bin/dash

##########################
#   tigger-status Test   #
##########################

trap 'rm -fr $output $expected $my $cse;exit' INT TERM EXIT

tigger=$(pwd)
my="$(mktemp -d)"
cse="$(mktemp -d)"

############################################################
# Test tigger-status: error: tigger repository directory .tigger not found
############################################################

cd "$my" || exit 1
output=$(mktemp)
"$tigger"/tigger-status > "$output" 2>&1

cd "$cse" || exit 1
expected=$(mktemp)
2041 tigger-status > "$expected" 2>&1

if ! diff "$output" "$expected"; then
    echo "test08-1: FAILED" 1>&2
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
# Test tigger-status: nothing
############################################################

cd "$my" || exit 1
output=$(mktemp)
"$tigger"/tigger-status > "$output" 2>&1

cd "$cse" || exit 1
expected=$(mktemp)
2041 tigger-status > "$expected" 2>&1

if ! diff "$output" "$expected"; then
    echo "test08-2: FAILED" 1>&2
    exit 1
fi

############################################################
# Test tigger-status: complex
############################################################

cd "$my" || exit 1
output=$(mktemp)
touch a b c d e f g h
"$tigger"/tigger-add a b c d e f
"$tigger"/tigger-commit -m 'first commit' >/dev/null
echo hello > a
echo hello > b
echo hello > c
"$tigger"/tigger-add a b
echo world > a
rm d
"$tigger"/tigger-rm e
"$tigger"/tigger-add g
"$tigger"/tigger-status > "$output" 2>&1

cd "$cse" || exit 1
expected=$(mktemp)
touch a b c d e f g h
2041 tigger-add a b c d e f
2041 tigger-commit -m 'first commit' >/dev/null
echo hello > a
echo hello > b
echo hello > c
2041 tigger-add a b
echo world > a
rm d
2041 tigger-rm e
2041 tigger-add g
2041 tigger-status > "$expected" 2>&1

if ! diff "$output" "$expected"; then
    echo "test08-3: FAILED" 1>&2
    exit 1
fi

echo "test08: ALL PASS" 1>&2
