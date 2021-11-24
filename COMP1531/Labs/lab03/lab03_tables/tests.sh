#!/bin/bash

regex='^(What[[:space:]]is[[:space:]][0-9]+[[:space:]]x[[:space:]][0-9]+\?[[:space:]]((Incorrect[[:space:]]-[[:space:]]try[[:space:]]again\.[[:space:]])|(Correct\!)))+$'
result=$(seq 2 144 | python3 tables.py)

[[ $result =~ $regex ]] && echo "Passed" || (echo "Failed"; exit 1)
