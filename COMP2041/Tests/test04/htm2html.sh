#! /bin/dash

for i in *.htm ; do
    new=$(echo "$i""l")
    if [ -f "$new" ] ; then
        echo "$new" "exists" 1>&2
        exit 1
    fi
    mv "$i" "$new"
done