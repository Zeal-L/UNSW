#! /bin/sh

if [ $# -ne 2 ]
then
    echo "Usage: $0 <year> <course-prefix>"
    exit 1
fi


if [ $(echo "$1" | grep -Ec "^[0-9]{4}$" ) -eq 0 ] || ! ([ "$1" -ge 2019 ] && [ "$1" -le 2022 ])
then
    echo "$0: argument 1 must be an integer between 2019 and 2022"
    exit 1
fi


undergraduate=https://www.handbook.unsw.edu.au/api/content/render/false/query/+unsw_psubject.implementationYear:$1%20+unsw_psubject.studyLevel:undergraduate%20+unsw_psubject.educationalArea:$2*%20+unsw_psubject.active:1%20+unsw_psubject.studyLevelValue:ugrd%20+deleted:false%20+working:true%20+live:true/orderby/unsw_psubject.code%20asc/limit/10000/offset/0
postgraduate=https://www.handbook.unsw.edu.au/api/content/render/false/query/+unsw_psubject.implementationYear:$1%20+unsw_psubject.studyLevel:postgraduate%20+unsw_psubject.educationalArea:$2*%20+unsw_psubject.active:1%20+unsw_psubject.studyLevelValue:pgrd%20+deleted:false%20+working:true%20+live:true/orderby/unsw_psubject.code%20asc/limit/10000/offset/0

curl -sL $undergraduate $postgraduate | 2041 jq -r '.contentlets | .[] | "\(.code) \(.title)"' | tr -s ' ' | sort | uniq