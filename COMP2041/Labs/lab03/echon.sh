#! /bin/sh
# Write a shell script called echon.sh which given exactly two arguments, 
# an integer n and a string, prints the string n times.

if [ $# -ne 2 ]
then
    echo "Usage: $0 <number of lines> <string>"
    exit 1
fi

if [ $( echo $1 | grep -E "^[0-9]+$" | wc -l ) -ne 1 ]
then
    echo "$0: argument 1 must be a non-negative integer"
    exit 1
fi



i=0
while (($i < $1)); do
    echo "$2"
    i=$((i+1))
done