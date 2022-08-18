#! /bin/dash

############################
#   tigger-checkout Test   #
############################

trap 'rm -fr $output $expected $my $cse;exit' INT TERM EXIT

tigger=$(pwd)
my="$(mktemp -d)"
cse="$(mktemp -d)"

############################################################
# Test tigger-branch: error: tigger repository directory .tigger not found
############################################################

cd "$my" || exit 1
output=$(mktemp)
"$tigger"/tigger-checkout output > "$output" 2>&1

cd "$cse" || exit 1
expected=$(mktemp)
2041 tigger-checkout expected > "$expected" 2>&1

if ! diff "$output" "$expected"; then
    echo "test03-1: FAILED" 1>&2
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
# add first commit
############################################################

cd "$my" || exit 1
echo "aaa" > a
"$tigger"/tigger-add a >/dev/null
"$tigger"/tigger-commit -m "x" >/dev/null
"$tigger"/tigger-branch new >/dev/null

cd "$cse" || exit 1
echo "aaa" > a
2041 tigger-add a >/dev/null
2041 tigger-commit -m "x" >/dev/null
2041 tigger-branch new >/dev/null

############################################################
# Test usage: tigger-checkout <branch>
############################################################

cd "$my" || exit 1
output=$(mktemp)
"$tigger"/tigger-checkout > "$output" 2>&1

cd "$cse" || exit 1
expected=$(mktemp)
2041 tigger-checkout > "$expected" 2>&1

if ! diff "$output" "$expected"; then
    echo "test03-2: FAILED" 1>&2
    exit 1
fi

############################################################
# Test tigger-checkout: error: unknown branch '$1'
############################################################

cd "$my" || exit 1
output=$(mktemp)
"$tigger"/tigger-checkout x > "$output" 2>&1

cd "$cse" || exit 1
expected=$(mktemp)
2041 tigger-checkout x > "$expected" 2>&1

if ! diff "$output" "$expected"; then
    echo "test03-3: FAILED" 1>&2
    exit 1
fi

############################################################
# Test success checkout to new branch
############################################################

cd "$my" || exit 1
output=$(mktemp)
"$tigger"/tigger-checkout new > "$output" 2>&1

cd "$cse" || exit 1
expected=$(mktemp)
2041 tigger-checkout new > "$expected" 2>&1

if ! diff "$output" "$expected"; then
    echo "test03-3: FAILED" 1>&2
    exit 1
fi

echo "test03: ALL PASS" 1>&2