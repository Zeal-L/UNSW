## Lab03 - Exercise - Times Tables Tester (1 point)

Write a program in `tables.py` that tests the user's knowledge of the time tables.

The program picks two random integers between 2 and 12 (see hint if stuck), and then asks the user to multiply them together in their head and then enter their answer.

If their result is correct it displays "Correct!", and if it's incorrect, it prompts them to try again (see sample interactions below).

```bash
$ python3 tables.py
What is 7 x 5? 34
Incorrect - try again.
What is 7 x 5? 33
Incorrect - try again.
What is 7 x 5? 35
Correct!
```

```bash
$ python3 tables.py
What is 3 x 3? 9
Correct!
```

The program will keep looping until they get the correct answer, and once they get the correct answer, the program will exit normally.

We have provided a file called `tests.sh` which will be run by the pipeline to tell whether or not your solution is correct. If you want to run this locally, run `bash tests.sh` in your terminal. The output of this script contains the difference between your output and the expected output.

We don't teach bash/shell in this course, so you're not expected to use this - if you get the red 'X' on the Gitlab pipeline, have a look at your code and try to figure out what is going wrong.

<details>
<summary>Hint</summary>

Hint 1: Random Module
```python
from random import randint
print(randint(1, 100))
```

Hint 2: While-true Loops
```python
while True:
    ...

    if condition:
        break
```

</details>
