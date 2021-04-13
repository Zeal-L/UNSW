#!/bin/sh

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
NC='\033[0m'

make testGirvanNewman || exit

run_test()
{
	i=$1
	rm -f "GirvanNewmanTests/$i.out"
    ./testGirvanNewman "graphs/$i.in" | sort -n > "GirvanNewmanTests/$i.out"
    
    if [ ! -f "GirvanNewmanTests/$i.exp" ]
	then
		echo -e "=========== ${YELLOW}[$i] No Expected Output Available${NC} ==========="
		return
	fi
	
    r="$(diff -B "GirvanNewmanTests/$i.out" "GirvanNewmanTests/$i.exp")"

    if [[ "$r" == "" ]]
    then
        echo -e "=========== ${GREEN}[$i] Output Matches${NC} ==========="
    else
        echo -e "=========== ${RED}[$i] Output Mismatch${NC} ==========="
        echo -e "${RED}Your output:${NC}"
		cat "GirvanNewmanTests/$i.out"
		echo -e "${RED}Expected output:${NC}"
		cat "GirvanNewmanTests/$i.exp"
        echo -e "${RED}Your output in: ./GirvanNewmanTests/$i.out${NC}"
        echo -e "${RED}Expected output in: ./GirvanNewmanTests/$i.exp${NC}"
    fi
}

if [ $# -eq 1 ]
then
	if [ ! -f "graphs/$1.in" ]
	then
		echo "error: graphs/$1.in does not exist"
		exit 1
	fi
	run_test $1
elif [ $# -eq 0 ]
then
	for f in graphs/*.in
	do
		i=$(basename "$f" .in)
		run_test "$i"
	done
else
	echo "usage: $0 <test number (1 for graphs/1.in, etc.)>"
	exit 1
fi

