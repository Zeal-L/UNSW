#! /bin/dash

dateInfo=$(ls -l "$1" | cut -d' ' -f6-8)

convert -gravity south -pointsize 36 -draw "text 0,10 '$dateInfo'" "$1" "$1"