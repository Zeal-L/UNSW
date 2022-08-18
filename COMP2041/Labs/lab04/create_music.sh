#! /bin/dash

info=$(wget -q -O- 'https://en.wikipedia.org/w/index.php?title=Triple_J_Hottest_100&oldid=1093287798&action=raw' | tail -n 652 | head -n 585)

mp3="$1"
dir="$2"
if [ ! -d "$2" ]; then
    mkdir "$2"
fi


echo "$info" | 
sed "/)]]'/,+11d" |
grep -E "([0-9]{4}\|[0-9]{4}\]\])|(^#)" | 
sed -E "s/.*('\[.*\]').*/\1/g" |
sed -E "s/(.*)\"\[\[.*\)\|(.*)/\1\"\[\[\2/g" |
sed -E "s/(.*)\[.*\(.*\)\|(.*)/\1\[\[\2/g" |

while read -r line; do
    
    if echo "$line" | grep -Eq "^'"; then
        if [ "$year" = "2019" ] && [ "$number" = "5" ]; then
            cp "$mp3" "$dir/$newdir/5 - Bulls on Parade (''Like a Version'') - Denzel Curry.mp3" || echo "error" 1>&2
            number=$((number + 1))
            continue
        fi
        if [ "$year" = "2021" ] && [ "$number" = "1" ]; then
            cp "$mp3" "$dir/$newdir/1 - Elephant (''Like a Version'') - The Wiggles.mp3" || echo "error" 1>&2
            number=$((number + 1))
            continue
        fi

        newdir=$(echo "$line" | sed -E "s/.*\[\[(.*)\|.*/\1/g")
        year=$(echo "$newdir" | cut -d',' -f2 | sed -E "s/ //")
        if [ ! -d "$dir"/"$newdir" ]; then
            mkdir "$dir"/"$newdir"
        fi
        number=0
    else
        title=$(echo "$line" | sed -E "s/.*\"(.*)\".*/\1/g" | sed -E "s/\[|\]//g" | sed -E "s/\//-/" | sed -E "s/.*\|//g")
        artist=$(echo "$line" | sed -E "s/\".*\"//g" | sed -E "s/(.*\w).*/\1/g" | sed -E "s/#|\[|\]//g" | sed -E "s/.*\|//g" | sed -E "s/(The White Stripes).*/\1/" | sed -E "s/^[\s].*w//")
        if [ "$title" = "Jolene" ]; then
            title="Jolene (Live)"
        fi
        if [ "$artist" = "Del tha Funkee Homosapien" ]; then
            artist="Gorillaz featuring Del tha Funkee Homosapien"
        fi
        if [ "$artist" = "Pharrell" ]; then
            artist="Daft Punk featuring Pharrell"
        fi
        
        newfile=$(echo "$number - $title - $artist" | sed -E "s/ -  / - /")
        if echo "$artist" | grep -Eq "Like a Version" ; then
            newfile="6 - Believe ('Like a Version'') - DMA's"
        fi

        album="$newdir"
        
        cp "$mp3" "$dir/$newdir/$newfile.mp3" || echo "error" 1>&2
        
        # id3 -t "$title" -T "$number" -a "$artist" -A "$newdir" -y "$year" -l "$dir/$newdir/$newfile.mp3" 1>/dev/null
    fi
    number=$((number + 1))
done
