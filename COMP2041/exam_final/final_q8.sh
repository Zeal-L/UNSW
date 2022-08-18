#! /bin/dash

list=''

check=0
for i in "$@"; do
    for j in "$@"; do
        if [ "$(echo "$list" | grep -Ec "$j")" -eq 0 ] && [ "$i" != "$j" ] && [ "$(diff "$i" "$j")" = '' ]; then
            echo "ln -s $i $j"
            list="$list $i $j"
            check=1
        fi
    done
done

if [ "$check" -eq 0 ]; then
    echo "No files can be replaced by symbolic links"
fi