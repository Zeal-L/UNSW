## Lab02 - Exercise - Tax (1 point)

Write a program `tax.py` that calculates tax you owe based on your taxable income in the 2017-2018 financial year.The tax brackets for the 2017-2018 financial year are as follows

![alt text](https://static.edusercontent.com/files/kLAg6L40Lt6NJzngOUsHwmDL "Tax calculations")

Your results should match the [simple tax calculator on the ATO website](https://www.ato.gov.au/calculators-and-tools/simple-tax-calculator/).

Here's a sample interaction:

```bash
Enter your income: 180000
The estimated tax on your income is $54,232.00
```

This program had the following standard input passed to it
```bash
180000
```
Note: You will have to do some research as to how to format numbers correctly.

We have provided a file called `tests.sh` which will be run by the pipeline to tell whether or not your solution is correct. If you want to run this locally, run `bash tests.sh` in your terminal. The output of this script contains the difference between your output and the expected output.

We don't teach bash/shell in this course, so you're not expected to use this - if you get the red 'X' on the Gitlab pipeline, have a look at your code and try to figure out what is going wrong.
