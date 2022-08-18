#! /bin/dash

tag() {
    cd "$1" || echo "error" 1>&2
    for file in *; do
        track=$(echo "$file" | cut -d '-' -f1 | sed 's/ $//')
        title=$(echo "$file" | cut -d '-' -f2 | sed 's/^ \| $//g')
        artist=$(echo "$file" | cut -d '-' -f3 | sed 's/^ \|.mp3$//g')
        album=$(echo "$1" | cut -d '/' -f2)
        year=$(echo "$1" | cut -d ',' -f2 | sed 's/^ //')
        id3 -t "$title" -T "$track" -a "$artist" -A "$album" -y "$year" -l "$file" 1>/dev/null
    done
    cd "../.." || echo "error" 1>&2
}

for d in "$@"; do
    tag "$d"
done



