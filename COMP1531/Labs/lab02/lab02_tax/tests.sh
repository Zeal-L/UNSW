#!/bin/bash

incomes=(
    180000
    20000
    500000
    100000
    80000
    36439
)
taxes=(
    "54,232.00"
    "342.00"
    "198,232.00"
    "24,632.00"
    "17,547.00"
    "3,465.41"
)

for ((i = 0; i < ${#incomes[@]}; i++)); do
    diff <(python3 tax.py <<< ${incomes[$i]}) <(echo "Enter your income: The estimated tax on your income is \$${taxes[$i]}")
done
