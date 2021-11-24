#!/bin/bash

for value in Nick Simon Hayden Emily Viv Kai "Marc Chee"
do
    diff <(python3 names.py <<< $value) <(echo "Name: So you call yourself $value huh?")
done
