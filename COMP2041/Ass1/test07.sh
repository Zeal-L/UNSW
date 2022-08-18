#! /bin/dash

########################
#   tigger-show Test   #
########################

trap 'rm -fr $output $expected $my $cse;exit' INT TERM EXIT

tigger=$(pwd)
my="$(mktemp -d)"
cse="$(mktemp -d)"

############################################################
# Test tigger-show: error: tigger repository directory .tigger not found
############################################################

cd "$my" || exit 1
output=$(mktemp)
"$tigger"/tigger-show > "$output" 2>&1

cd "$cse" || exit 1
expected=$(mktemp)
2041 tigger-show > "$expected" 2>&1

if ! diff "$output" "$expected"; then
    echo "test07-1: FAILED" 1>&2
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
# Test usage: tigger-show <commit>:<filename>
############################################################

cd "$my" || exit 1
output=$(mktemp)
"$tigger"/tigger-show > "$output" 2>&1

cd "$cse" || exit 1
expected=$(mktemp)
2041 tigger-show > "$expected" 2>&1

if ! diff "$output" "$expected"; then
    echo "test07-2: FAILED" 1>&2
    exit 1
fi

############################################################
# Test tigger-show: error: invalid object $1
############################################################

cd "$my" || exit 1
output=$(mktemp)
"$tigger"/tigger-show "x"> "$output" 2>&1

cd "$cse" || exit 1
expected=$(mktemp)
2041 tigger-show "x" > "$expected" 2>&1

if ! diff "$output" "$expected"; then
    echo "test07-3: FAILED" 1>&2
    exit 1
fi

############################################################
# Test tigger-show: error: '$fileName' not found in index
############################################################

cd "$my" || exit 1
output=$(mktemp)
"$tigger"/tigger-show ":x"> "$output" 2>&1

cd "$cse" || exit 1
expected=$(mktemp)
2041 tigger-show ":x" > "$expected" 2>&1

if ! diff "$output" "$expected"; then
    echo "test07-4: FAILED" 1>&2
    exit 1
fi

############################################################
# Test tigger-show: error: unknown commit '$commit'
############################################################

cd "$my" || exit 1
output=$(mktemp)
"$tigger"/tigger-show "9:x"> "$output" 2>&1

cd "$cse" || exit 1
expected=$(mktemp)
2041 tigger-show "9:x" > "$expected" 2>&1

if ! diff "$output" "$expected"; then
    echo "test07-5: FAILED" 1>&2
    exit 1
fi


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
# Test tigger-show: error: invalid filename '$fileName'
############################################################

cd "$my" || exit 1
output=$(mktemp)
"$tigger"/tigger-show "0:x/" > "$output" 2>&1

cd "$cse" || exit 1
expected=$(mktemp)
2041 tigger-show "0:x/" > "$expected" 2>&1


if ! diff "$output" "$expected"; then
    echo "test07-6: FAILED" 1>&2
    exit 1
fi

############################################################
# Test tigger-show: error: '$fileName' not found in commit $commit
############################################################

cd "$my" || exit 1
output=$(mktemp)
"$tigger"/tigger-show "0:x"> "$output" 2>&1

cd "$cse" || exit 1
expected=$(mktemp)
2041 tigger-show "0:x" > "$expected" 2>&1

if ! diff "$output" "$expected"; then
    echo "test07-7: FAILED" 1>&2
    exit 1
fi

############################################################
# Test successfully show the file a in commit 0
############################################################

cd "$my" || exit 1
output=$(mktemp)
"$tigger"/tigger-show "0:a"> "$output" 2>&1

cd "$cse" || exit 1
expected=$(mktemp)
2041 tigger-show "0:a" > "$expected" 2>&1

if ! diff "$output" "$expected"; then
    echo "test07-8: FAILED" 1>&2
    exit 1
fi

echo "test07: ALL PASS" 1>&2