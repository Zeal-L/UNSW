#! /bin/dash

for jpg in *.jpg
do
    png="${jpg%.jpg}.png"
    if [ -f "$png" ]
    then
        echo "$png" already exists 2>&1
        exit 1
    fi
    convert "$jpg" "$png" 2>/dev/null
done
rm ./*.jpg
