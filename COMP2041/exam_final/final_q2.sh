#! /bin/dash

cat $1 | grep -e 'M$' | cut -d'|' -f3 | cut -d',' -f1 |sort | uniq