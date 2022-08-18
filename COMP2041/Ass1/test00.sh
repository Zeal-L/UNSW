#! /bin/dash

#######################
#  tigger-init Test   #
#######################

trap 'rm -fr $output $expected $my $cse;exit' INT TERM EXIT

tigger=$(pwd)
my="$(mktemp -d)"
cse="$(mktemp -d)"


############################################################
# Test Initialized empty tigger repository in .tigger
############################################################

cd "$my" || exit 1
output=$(mktemp)
"$tigger"/tigger-init > "$output" 2>&1

cd "$cse" || exit 1
expected=$(mktemp)
2041 tigger-init > "$expected" 2>&1


if ! diff "$output" "$expected"; then
    echo "test00-1: FAILED" 1>&2
    exit 1
fi

############################################################
# Test tigger-init: error: .tigger already exists
############################################################

cd "$my" || exit 1
output=$(mktemp)
"$tigger"/tigger-init > "$output" 2>&1

cd "$cse" || exit 1
expected=$(mktemp)
2041 tigger-init > "$expected" 2>&1

if ! diff "$output" "$expected"; then
    echo "test00-2: FAILED" 1>&2
    exit 1
fi

echo "test00: ALL PASS" 1>&2