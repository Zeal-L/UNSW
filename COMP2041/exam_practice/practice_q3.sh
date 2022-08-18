#! /bin/dash

for dic in ./*; do
    if [ -d "$dic" ]; then
        if [ "$(find "$dic" -maxdepth 1 | wc -l)" -gt 2 ]; then
            basename "$dic"
        fi
    fi
done