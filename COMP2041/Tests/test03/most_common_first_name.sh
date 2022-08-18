#!/bin/dash

cat $1  | grep 'COMP[29]041' | cut -d' ' -f2 | sort | uniq -c | sort | tail -1 | sed 's/[0-9 ]//g' 