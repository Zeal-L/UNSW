#! /bin/dash

cat "$@" | cut -d'|' -f4 | cut -d'/' -f1 | sort | 
grep -e '3711' | echo $(uniq -c) | cut -d' ' -f1