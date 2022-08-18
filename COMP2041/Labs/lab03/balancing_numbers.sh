#! /bin/sh
# map all digit characters whose values are less than 5 into the character '<'.
# map all digit characters whose values are greater than 5 into the character '>'.
# leave the digit character '5', and all non-digit characters, unchanged.

while read line
do
	echo "$line" | sed 's/[0-4]/</g' | sed 's/[6-9]/>/g'
done