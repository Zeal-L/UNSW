## Lab01 - Exercise - Name

### Printing multiple strings

```python
print("Harry" + "Potter")
HarryPotter
```

Notice that this doesn't add any extra spaces, you need to add them yourself if you want some:

```python
print("Harry" + " " + "Potter") # => Harry Potter
print("Harry", "Potter") # => Harry Potter
name = "Harry Potter"
print(f"Hello, {name}") # => Hello, Harry Potter
```

### Name

Task: Write a program that takes someone’s name as input and prints
“So you call yourself {name} huh?”

Example

```
Name: Marc Chee
So you call yourself Marc Chee huh?
```

We have provided a file called `tests.sh` which will be run by the pipeline to tell whether or not your solution is correct. If you want to run this locally, run `bash tests.sh` in your terminal. The output of this script contains the difference between your output and the expected output.

We don't teach bash/shell in this course, so you're not expected to use this - if you get the red 'X' on the Gitlab pipeline, have a look at your code and try to figure out what is going wrong.
