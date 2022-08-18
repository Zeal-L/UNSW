#! /bin/dash

curl --location --silent "http://www.timetable.unsw.edu.au/2022/$1KENS.html" |
grep -E "$1.*" | 
sed -E 's/.*html\">(.*)<\/a>.*/\1/' | 
sed -n '{N;s/\n/\t/p}' | 
sort | uniq