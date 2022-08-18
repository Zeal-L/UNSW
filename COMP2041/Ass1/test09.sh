#! /bin/dash

###########################
#   Complex tigger Test   #
###########################

trap 'rm -fr $output $expected $my $cse;exit' INT TERM EXIT

tigger=$(pwd)
my="$(mktemp -d)"
cse="$(mktemp -d)"

############################################################
# Initializa empty tigger repository in .tigger
############################################################

cd "$my" || exit 1
"$tigger"/tigger-init 1>/dev/null

cd "$cse" || exit 1
2041 tigger-init 1>/dev/null

############################################################
# Test 01
############################################################

cd "$my" || exit 1
output=$(mktemp)
touch a
"$tigger"/tigger-add a
"$tigger"/tigger-commit -m commit-0 1>/dev/null

"$tigger"/tigger-branch b1
"$tigger"/tigger-checkout b1 1>/dev/null
touch b
"$tigger"/tigger-add b
"$tigger"/tigger-commit -m commit-1 1>/dev/null 
"$tigger"/tigger-checkout master 1>/dev/null

"$tigger"/tigger-branch b2
"$tigger"/tigger-checkout b2 1>/dev/null
touch c
"$tigger"/tigger-add c
"$tigger"/tigger-commit -m commit-2 1>/dev/null

"$tigger"/tigger-checkout b1 1>/dev/null
"$tigger"/tigger-status > "$output" 2>&1

cd "$cse" || exit 1
expected=$(mktemp)
touch a
2041 tigger-add a
2041 tigger-commit -m commit-0 1>/dev/null

2041 tigger-branch b1
2041 tigger-checkout b1 1>/dev/null
touch b
2041 tigger-add b
2041 tigger-commit -m commit-1 1>/dev/null 
2041 tigger-checkout master 1>/dev/null

2041 tigger-branch b2
2041 tigger-checkout b2 1>/dev/null
touch c
2041 tigger-add c
2041 tigger-commit -m commit-2 1>/dev/null

2041 tigger-checkout b1 1>/dev/null
2041 tigger-status > "$expected" 2>&1

if ! diff "$output" "$expected"; then
    echo "test09-1: FAILED" 1>&2
    exit 1
fi

############################################################
# Test 02
############################################################

cd "$my" || exit 1
output=$(mktemp)
"$tigger"/tigger-checkout b1 1>/dev/null
"$tigger"/tigger-rm --force --cached a
"$tigger"/tigger-checkout master 1>/dev/null
cat a > "$output" 2>&1

cd "$cse" || exit 1
expected=$(mktemp)
2041 tigger-checkout b1 1>/dev/null
2041 tigger-rm --force --cached a
2041 tigger-checkout master 1>/dev/null
cat a > "$expected" 2>&1

if ! diff "$output" "$expected"; then
    echo "test09-1: FAILED" 1>&2
    exit 1
fi

echo "test09: ALL PASS" 1>&2
