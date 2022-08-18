#! /bin/sh

small=""
medium=""
large=""

for file in *
do
    if [ -f $file ] 
    then
        if [ $(cat $file | wc -l) -lt 10 ] 
        then
            small+="$file "
        elif [ $(cat $file | wc -l) -lt 100 ] 
        then
            medium+="$file "
        else
            large+="$file "
        fi
    fi
done

echo "Small files: $small"
echo "Medium-sized files: $medium"
echo "Large files: $large"