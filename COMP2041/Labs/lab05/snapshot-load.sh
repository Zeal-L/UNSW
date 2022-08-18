#! /bin/dash

save() {
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
}
save

if [ ! -d ".snapshot.$1" ]; then
    echo "Snapshot $1 not found"
    exit 1
fi

echo "Restoring snapshot $1"
for i in ".snapshot.$1"/*; do
    dest=$(pwd "/$i")
    cp "$i" "$dest"
done
