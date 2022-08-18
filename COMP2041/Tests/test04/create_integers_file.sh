#! /bin/dash

i=$1
while [ $i -le $2 ]; do
    echo $i >> $3
    i=$(($i+1))
done

