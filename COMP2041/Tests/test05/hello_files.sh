#! /bin/dash

num=$1
name=$2
i=1
while [ $i -le "$num" ] ; do
    file="hello$i.txt"
    echo "hello" "$name" > $file
    i=$((i+1))
done