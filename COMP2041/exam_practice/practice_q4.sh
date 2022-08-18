#! /bin/dash

n=$1
m=$2

nn=$(echo "$n" | sed 's/[^0-9]//g')
mm=$(echo "$m" | sed 's/[^0-9]//g')
i=$nn

while [ "$i" -le "$mm" ]; do
    echo "$n" | sed -E "s/$nn/$i/"
    i=$((i+1))
done

