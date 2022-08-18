#! /bin/dash

#########################
#  tigger-branch Test   #
#########################

trap 'rm -fr $output $expected $my $cse;exit' INT TERM EXIT

tigger=$(pwd)
my="$(mktemp -d)"
cse="$(mktemp -d)"


############################################################
# Test tigger-branch: error: tigger repository directory .tigger not found
############################################################

cd "$my" || exit 1
output=$(mktemp)
"$tigger"/tigger-branch output > "$output" 2>&1

cd "$cse" || exit 1
expected=$(mktemp)
2041 tigger-branch expected > "$expected" 2>&1

if ! diff "$output" "$expected"; then
    echo "test02-1: FAILED" 1>&2
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
# Test tigger-branch: error: this command can not be run until after the first commit
############################################################

cd "$my" || exit 1
output=$(mktemp)
"$tigger"/tigger-branch output > "$output" 2>&1

cd "$cse" || exit 1
expected=$(mktemp)
2041 tigger-branch expected > "$expected" 2>&1

if ! diff "$output" "$expected"; then
    echo "test02-2: FAILED" 1>&2
    exit 1
fi

############################################################
# add first commit
############################################################

cd "$my" || exit 1
echo "aaa" > a
"$tigger"/tigger-add a >/dev/null
"$tigger"/tigger-commit -m "x" >/dev/null

cd "$cse" || exit 1
echo "aaa" > a
2041 tigger-add a >/dev/null
2041 tigger-commit -m "x" >/dev/null

############################################################
# Test usage: tigger-branch [-d] <branch>
############################################################

cd "$my" || exit 1
output=$(mktemp)
"$tigger"/tigger-branch -x output > "$output" 2>&1

cd "$cse" || exit 1
expected=$(mktemp)
2041 tigger-branch -x expected > "$expected" 2>&1

if ! diff "$output" "$expected"; then
    echo "test02-3: FAILED" 1>&2
    exit 1
fi

############################################################
# Test tigger-branch: error: invalid filename
############################################################

cd "$my" || exit 1
output=$(mktemp)
"$tigger"/tigger-branch "/:/" > "$output" 2>&1

cd "$cse" || exit 1
expected=$(mktemp)
2041 tigger-branch "/:/" > "$expected" 2>&1

if ! diff "$output" "$expected"; then
    echo "test02-4: FAILED" 1>&2
    exit 1
fi

############################################################
# Test tigger-branch: error: branch name required
############################################################

cd "$my" || exit 1
output=$(mktemp)
"$tigger"/tigger-branch -d > "$output" 2>&1

cd "$cse" || exit 1
expected=$(mktemp)
2041 tigger-branch -d > "$expected" 2>&1

if ! diff "$output" "$expected"; then
    echo "test02-5: FAILED" 1>&2
    exit 1
fi

############################################################
# Test tigger-branch: error: branch '$1' already exists
############################################################

cd "$my" || exit 1
output=$(mktemp)
"$tigger"/tigger-branch master > "$output" 2>&1

cd "$cse" || exit 1
expected=$(mktemp)
2041 tigger-branch master > "$expected" 2>&1

if ! diff "$output" "$expected"; then
    echo "test02-6: FAILED" 1>&2
    exit 1
fi

############################################################
# Test tigger-branch: error: branch '$2' doesn't exist
############################################################

cd "$my" || exit 1
output=$(mktemp)
"$tigger"/tigger-branch -d x > "$output" 2>&1

cd "$cse" || exit 1
expected=$(mktemp)
2041 tigger-branch -d x > "$expected" 2>&1

if ! diff "$output" "$expected"; then
    echo "test02-7: FAILED" 1>&2
    exit 1
fi

############################################################
# Test tigger-branch: error: can not delete branch 'master'
############################################################

cd "$my" || exit 1
output=$(mktemp)
"$tigger"/tigger-branch -d master > "$output" 2>&1

cd "$cse" || exit 1
expected=$(mktemp)
2041 tigger-branch -d master > "$expected" 2>&1

if ! diff "$output" "$expected"; then
    echo "test02-8: FAILED" 1>&2
    exit 1
fi

############################################################
# Test printout all branch names
############################################################

cd "$my" || exit 1
output=$(mktemp)
"$tigger"/tigger-branch > "$output" 2>&1

cd "$cse" || exit 1
expected=$(mktemp)
2041 tigger-branch > "$expected" 2>&1

if ! diff "$output" "$expected"; then
    echo "test02-9: FAILED" 1>&2
    exit 1
fi

############################################################
# Test Deleted branch
############################################################

cd "$my" || exit 1
output=$(mktemp)
"$tigger"/tigger-branch new >/dev/null
"$tigger"/tigger-branch -d new > "$output" 2>&1

cd "$cse" || exit 1
expected=$(mktemp)
2041 tigger-branch new >/dev/null
2041 tigger-branch -d new > "$expected" 2>&1

if ! diff "$output" "$expected"; then
    echo "test02-10: FAILED" 1>&2
    exit 1
fi

echo "test02: ALL PASS" 1>&2