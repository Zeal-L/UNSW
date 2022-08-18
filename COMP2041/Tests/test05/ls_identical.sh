#! /bin/dash

for f1 in "$1"/*; do
    for f2 in "$2"/*; do
        # compare file name
        if [ "$(basename "$f1")" = "$(basename "$f2")" ]; then
            # compare file content
            if cmp -s "$f1" "$f2"; then
                basename "$f1"
            fi
        fi
    done
done
