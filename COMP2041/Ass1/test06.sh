#! /bin/dash

#######################
#   tigger-rm Test   #
#######################

trap 'rm -fr $output $expected $my $cse;exit' INT TERM EXIT

tigger=$(pwd)
my="$(mktemp -d)"
cse="$(mktemp -d)"

############################################################
# Test tigger-rm: error: tigger repository directory .tigger not found
############################################################

cd "$my" || exit 1
output=$(mktemp)
"$tigger"/tigger-rm > "$output" 2>&1

cd "$cse" || exit 1
expected=$(mktemp)
2041 tigger-rm > "$expected" 2>&1

if ! diff "$output" "$expected"; then
    echo "test06-1: FAILED" 1>&2
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
# Test usage: tigger-rm [--force] [--cached] <filenames>
############################################################

cd "$my" || exit 1
output=$(mktemp)
"$tigger"/tigger-rm --x x > "$output" 2>&1

cd "$cse" || exit 1
expected=$(mktemp)
2041 tigger-rm --x x > "$expected" 2>&1

if ! diff "$output" "$expected"; then
    echo "test06-2: FAILED" 1>&2
    exit 1
fi

############################################################
# Test tigger-rm: error: invalid filename '$file'
############################################################

cd "$my" || exit 1
output=$(mktemp)
"$tigger"/tigger-rm "//" > "$output" 2>&1

cd "$cse" || exit 1
expected=$(mktemp)
2041 tigger-rm "//" > "$expected" 2>&1

if ! diff "$output" "$expected"; then
    echo "test06-3: FAILED" 1>&2
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
# Test tigger-rm: error: '$target' in the repository is different to the working file
############################################################

cd "$my" || exit 1
output=$(mktemp)
echo "bbb" > a
"$tigger"/tigger-rm "a" > "$output" 2>&1

cd "$cse" || exit 1
expected=$(mktemp)
echo "bbb" > a
2041 tigger-rm "a" > "$expected" 2>&1

if ! diff "$output" "$expected"; then
    echo "test06-4: FAILED" 1>&2
    exit 1
fi

############################################################
# Test tigger-rm: error: '$target' in index is different to both the working file and the repository
############################################################

cd "$my" || exit 1
output=$(mktemp)
"$tigger"/tigger-add a
echo "aaa" > a
"$tigger"/tigger-rm "a" > "$output" 2>&1

cd "$cse" || exit 1
expected=$(mktemp)
2041 tigger-add a
echo "aaa" > a
2041 tigger-rm "a" > "$expected" 2>&1

if ! diff "$output" "$expected"; then
    echo "test06-5: FAILED" 1>&2
    exit 1
fi

############################################################
# Test tigger-rm: error: '$target' has staged changes in the index
############################################################

cd "$my" || exit 1
output=$(mktemp)
echo "bbb" > a
"$tigger"/tigger-rm "a" > "$output" 2>&1

cd "$cse" || exit 1
expected=$(mktemp)
echo "bbb" > a
2041 tigger-rm "a" > "$expected" 2>&1

if ! diff "$output" "$expected"; then
    echo "test06-6: FAILED" 1>&2
    exit 1
fi

############################################################
# Test tigger-rm: --cached
############################################################

cd "$my" || exit 1
output=$(mktemp)
echo "bbb" > a
"$tigger"/tigger-rm --cached a
"$tigger"/tigger-show :a > "$output" 2>&1

cd "$cse" || exit 1
expected=$(mktemp)
echo "bbb" > a
2041 tigger-rm --cached a
2041 tigger-show :a > "$expected" 2>&1

if ! diff "$output" "$expected"; then
    echo "test06-7: FAILED" 1>&2
    exit 1
fi

############################################################
# Test tigger-rm: --force
############################################################

cd "$my" || exit 1
output=$(mktemp)
echo "ccc" > a
"$tigger"/tigger-add a
"$tigger"/tigger-rm --force a > "$output" 2>&1

cd "$cse" || exit 1
expected=$(mktemp)
echo "ccc" > a
2041 tigger-add a
2041 tigger-rm --force a > "$expected" 2>&1

if ! diff "$output" "$expected"; then
    echo "test06-8: FAILED" 1>&2
    exit 1
fi

cd "$my" || exit 1
output=$(mktemp)
"$tigger"/tigger-show :a > "$output" 2>&1

cd "$cse" || exit 1
expected=$(mktemp)
2041 tigger-show :a > "$expected" 2>&1

if ! diff "$output" "$expected"; then
    echo "test06-8: FAILED" 1>&2
    exit 1
fi

echo "test06: ALL PASS" 1>&2