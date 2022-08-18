#! /bin/dash

for i in "$@"; do
    cat $i |
    while read -r line; do
        check=$(echo $line | grep -o '#include ".*"' | sed -E 's/.*"(.*)".*/\1/')
        if [ ! -f $check ]; then 
            echo $check "included into" $i "does not exist"
        fi
    done
done