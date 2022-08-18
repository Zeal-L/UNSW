#! /bin/dash

i=0
while true; do
    new=".snapshot.$i"
    if [ -d "$new" ]; then
        i=$((i + 1))
        continue
    else
        echo "Creating snapshot $i"
        mkdir "$new"
        break
    fi
done

for i in *; do
    if [ "$i" = "snapshot-save.sh" ] ||
        [ "$i" = "snapshot-load.sh" ] ||
        [ "$(echo "$i" | grep -Ec '^\.')" -eq 1 ]; then
        continue
    fi
    cp "$i" "$new"
done
