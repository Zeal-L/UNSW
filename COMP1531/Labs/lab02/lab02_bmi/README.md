## Lab02 - Exercise - BMI (1 point)

Write a program `bmi.py` that calculates the user's BMI (body mass index). The formula is:

*BMI = weight in kilograms / (height in metres * height in metres)*

The program takes in a weight and a height from stdin and produces an output.

For example
```bash
What is your weight in kg? 70
What is your height in m? 1.82
Your BMI is 21.1
```

Hints:
* Remember that you can convert the return value of the function `input()` to an `int` or any other numerical type
* The `round` function takes in 2 parameters - the number to be rounded, and the number of decimal places.

We have provided a file called `tests.sh` which will be run by the pipeline to tell whether or not your solution is correct. If you want to run this locally, run `bash tests.sh` in your terminal. The output of this script contains the difference between your output and the expected output.

We don't teach bash/shell in this course, so you're not expected to use this - if you get the red 'X' on the Gitlab pipeline, have a look at your code and try to figure out what is going wrong.