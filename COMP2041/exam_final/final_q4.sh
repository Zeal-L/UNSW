#! /bin/dash

check=0

cat "$1" | sort -n |
while read line; do
    if [ "$check" = 0 ]; then
        check=1
    else
        temp=$(($last_line + 1))
        while [ "$line" -ne "$temp" ]; do
            echo "$temp"
            temp=$(($temp + 1))
        done
    fi
    last_line="$line"
done