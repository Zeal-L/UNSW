#!/bin/bash

weights=(
    30
    75
    100
    0
    90
)
heights=(
    1.6
    1.9
    1.5
    1
    1.9
)
answers=(
    11.7
    20.8
    44.4
    0.0
    24.9
)

for ((i = 0; i < ${#weights[@]}; i++)); do
    diff <(echo -e "${weights[$i]}\n${heights[$i]}" | python3 bmi.py) <(echo "What is your weight in kg? What is your height in m? Your BMI is ${answers[$i]}")
done
