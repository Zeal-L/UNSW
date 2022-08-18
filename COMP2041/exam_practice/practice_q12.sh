#! /bin/dash


cat "$1" |
while read -r line; do
    echo "$line"
done

