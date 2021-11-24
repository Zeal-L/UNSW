## Lab09 - Exercise - Light Up: Solver (5 points)

Back in Week 2, one of the challenge exercises was to write a program to tell the [board state](https://gitlab.cse.unsw.edu.au/COMP1531/21T1/STAFF/repos/lab-02-lightup) in a game of Light Up.

For this question, you will need to write a solver for a board of Light Up.

In `lightup.py`, write a function `solve(board)` which takes in a board of containing a list of strings, each string being a row of the board. The return value should be the solved board.

* The board will use the same input format as the previous question, except the input board will not contain any lamps
* The input board is guaranteed to be solvable

Here is the [helper website](https://groklearning.github.io/problem-helpers/light-up/) from the previous question.

Here are two examples of how your program should work:

```python
>>> solve('''...1.0.
X......
..X.X..
X.....X
..X.3..
......X
.3.2...''')
..L1.0.
X...L..
L.X.X.L
X...L.X
..XL3L.
.L....X
L3L2L..
>>> solve('''...
.4.
...''')
.L.
L4L
.L.
```

There are no tests for this question. During your lab marking, you will need to show your program working with two different test cases you have constructed.
