#!/bin/bash
tests=(
    "L\nL\nL\nC"
    "L\nH\nH\nC"
    "H\nL\nH\nL\nL\nC"
    "L\nL\nL\nL\nC"
)
regex='^Pick[[:space:]]a[[:space:]]number[[:space:]]between[[:space:]]1[[:space:]]and[[:space:]]100[[:space:]]\(inclusive\)[[:space:]]My[[:space:]]guess[[:space:]]is:[[:space:]][0-9]+[[:space:]](Is[[:space:]]my[[:space:]]guess[[:space:]]too[[:space:]]low[[:space:]]\(L\),[[:space:]]too[[:space:]]high[[:space:]]\(H\),[[:space:]]or[[:space:]]correct[[:space:]]\(C\)\?[[:space:]]My[[:space:]]guess[[:space:]]is:[[:space:]][0-9]+[[:space:]])+Is[[:space:]]my[[:space:]]guess[[:space:]]too[[:space:]]low[[:space:]]\(L\),[[:space:]]too[[:space:]]high[[:space:]]\(H\),[[:space:]]or[[:space:]]correct[[:space:]]\(C\)\?[[:space:]]Got[[:space:]]it\!$'

for ((i = 0; i < ${#tests[@]}; i++)); do
    result=$(echo -e ${tests[$i]} | python3 guess.py)
    [[ $result =~ $regex ]] && echo "Test passed" || (echo "Test failed" 1>&2; exit 1)
done
