#! /bin/dash

pattern=$1
check=0

ckkk=$(grep -E "$pattern" "$2" | cut -d'|' -f2 | sort -n | uniq | wc -l)

if [ "$ckkk" = 0 ]; then
    echo "No award matching '$1'"
    exit 0
fi

grep -E "$pattern" "$2" | cut -d'|' -f2 | sort -n | uniq |
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