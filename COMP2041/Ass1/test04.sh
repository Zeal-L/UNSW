#! /bin/dash

##########################
#   tigger-commit Test   #
##########################

trap 'rm -fr $output $expected $my $cse;exit' INT TERM EXIT

tigger=$(pwd)
my="$(mktemp -d)"
cse="$(mktemp -d)"

############################################################
# Test tigger-commit: error: tigger repository directory .tigger not found
############################################################

cd "$my" || exit 1
output=$(mktemp)
"$tigger"/tigger-commit -m "x" > "$output" 2>&1

cd "$cse" || exit 1
expected=$(mktemp)
2041 tigger-commit -m "x" > "$expected" 2>&1

if ! diff "$output" "$expected"; then
    echo "test04-1: FAILED" 1>&2
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
# Test usage: tigger-commit [-a] -m commit-message
############################################################

cd "$my" || exit 1
output=$(mktemp)
"$tigger"/tigger-commit > "$output" 2>&1

cd "$cse" || exit 1
expected=$(mktemp)
2041 tigger-commit > "$expected" 2>&1

if ! diff "$output" "$expected"; then
    echo "test04-2: FAILED" 1>&2
    exit 1
fi

############################################################
# Test nothing to commit
############################################################

cd "$my" || exit 1
output=$(mktemp)
"$tigger"/tigger-commit -m "x" > "$output" 2>&1

cd "$cse" || exit 1
expected=$(mktemp)
2041 tigger-commit -m "x" > "$expected" 2>&1

if ! diff "$output" "$expected"; then
    echo "test04-3: FAILED" 1>&2
    exit 1
fi

############################################################
# Test Successfully commit changes
############################################################

cd "$my" || exit 1
output=$(mktemp)
echo "aaa" > a
"$tigger"/tigger-add a >/dev/null
"$tigger"/tigger-commit -m "x" >/dev/null
"$tigger"/tigger-show :a > "$output" 2>&1

cd "$cse" || exit 1
expected=$(mktemp)
echo "aaa" > a
2041 tigger-add a >/dev/null
2041 tigger-commit -m "x" >/dev/null
2041 tigger-show :a > "$expected" 2>&1

if ! diff "$output" "$expected"; then
    echo "test04-4: FAILED" 1>&2
    exit 1
fi

echo "test04: ALL PASS" 1>&2