#! /bin/dash

max=0
for i in "$@"; do
    info=$(wc -l "$i" | cut -d ' ' -f1)
    if [ "$info" -gt "$max" ]; then
        max=$info
        file=$i
    fi
done

echo "$file"