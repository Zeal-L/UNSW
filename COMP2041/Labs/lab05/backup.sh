#! /bin/dash

i=0
while true; do
    new=$(echo ".$1.$i")
    if [ -f "$new" ]; then
        i=$((i + 1))
        continue
    else
        echo "Backup of '$1' saved as '$new'"
        cat "$1" >"$new"
        break
    fi
done
