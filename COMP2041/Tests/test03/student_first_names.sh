#!/bin/dash

cat $1 | cut -d '|' -f2-3 | sort | uniq | cut -d '|' -f2 | cut -d ',' -f2 | cut -d ' ' -f2 | sort