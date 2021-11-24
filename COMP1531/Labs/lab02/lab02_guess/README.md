## Lab02 - Exercise - Guess (2 points)

Open `guess.py`.

Write a program in `guess.py` that asks the user to think of a number between 1 and 100 (inclusive). The program should then repeatedly guess a number, and have the user say whether the guess is too low, too high or correct. Example:

```bash
Pick a number between 1 and 100 (inclusive)
My guess is: 50
Is my guess too low (L), too high (H), or correct (C)?
L
My guess is: 75
Is my guess too low (L), too high (H), or correct (C)?
H
My guess is: 62
Is my guess too low (L), too high (H), or correct (C)?
C
Got it!
```

This program had the following standard input passed to it
```bash
L
H
C
```

You should not use the `random` module to solve this exercise.

We have provided a file called `tests.sh` which will be run by the pipeline to tell whether or not your solution is correct. If you want to run this locally, run `bash tests.sh` in your terminal. The output of this script contains the difference between your output and the expected output.

We don't teach bash/shell in this course, so you're not expected to use this - if you get the red 'X' on the Gitlab pipeline, have a look at your code and try to figure out what is going wrong.
