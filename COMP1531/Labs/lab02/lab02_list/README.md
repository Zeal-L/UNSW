## Lab02 - Exercise - List (1 point)

Open `list_exercises.py`.

### Step 1 - Run the Failing Unit Tests

You have been provided with some examples of tests. Run these tests using the command `pytest`, or `python3 -m pytest` if the former doesn't work. You will see that the tests fail. This is because we haven't implemented the functions yet.

### Step 2 - Implement the Code and Pass the Tests

Implement the function stubs using only **one** line of python.

Run these tests with `pytest` to ensure they pass.

### Step 3 - Write More Tests

Now, in `test_list_exericses.py` add more to each test to make the test suite more exhaustive. Try to add:

* At least two more assert statements for each test, and
* Another test function

When writing a test, consider the following things:

* Do the assertions I'm making in the test body match what the test name (function name) says I am testing?
* Does the name of my test provide specific detail to someone reading it?
* Is my function testing one thing, or several things which could be split into smaller tests?

### Final Step

Commit and push your code to the master branch of this repository. The code on your master branch on Gitlab is what will be submitted at the deadline. The pipeline for this repo will run `pytest`, so use it to check you've implemented everything.
