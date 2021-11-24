## Lab01 - Exercise - Strings (1 point)

Unlike a C string, a string in Python is not merely a pointer to a block of NULL-terminated characters (Python does not have pointers), but rather a built-in datatype similar to a list. They also have a lot of in built functionality like concatenation (appending one string to another) and making all characters lower case, for example.

Strings can be indexed with both positive and negative indices. Positive indices work like you would expect, starting at 0 and ending at 1 minus the length of the string. Negative indexes start at -1 and work their way from the back of the strings.

You can also get a range of characters from a string using the syntax `[begin:end]` (begin is included and end is excluded).

```python
test = "hey there you!"
print(test[0]) # Will print 'h'
print(test[1]) # Will print 'e'
print(test[-1]) # Will print '!'
print(test[-2]) # Will print 'u'

print(test[0:3]) # Will print 'hey'
print(test[:3]) # Will print 'hey' since an empty begin defaults to 0

print(test[:-1]) # Will print 'hey there you'
print(test[1:]) # Will print 'ey there you!' since empty end defaults to the end
```

**NOTE:** The same syntax can be used for elements in a list

The file `strings.py` has a list of strings that you will need to print out space separated. The **expected output** is:

> This list is now all together

Note that there is **NO** trailing space in the output.

### Instructions

1. Open the `strings.py` file
2. Use a `for` loop to join all of the strings, separated by a space.
3. Print the new string such that the output matches the above (no trailing space in output).

At this point you should commit and push your changes to Gitlab. However, for this exercise your repo has been given a *Continuous Integration pipeline*. You will learn what this is and how it works as you progress through the course, but for now the important fact is that every time you push to your Gitlab repo, some checks will be performed on your code. For this lab, the only check is that your `strings.py` has the correct output.

You can see the status of your pipeline by looking at the top left of this page in Gitlab. It will say either:

* ![passed](pipeline-passed.svg) if the contents of the master branch passed the checks.
* ![failed](pipeline-failed.svg) if the contents of the master branch failed the checks.
* ![running](pipeline-running.svg) if the checks are still running.

Currently, it says "failed", but that's because you need to push your completed code. Once you push, it should change to running (or possibly "pending", if a lot of other people are running pipelines at the same time), then, shortly afterward, to "passed". Note that you may have to refresh the page to see it.

If it doesn't change to "passed", you will get an email telling you that your pipeline has failed. Double check that you're program is producing the correct output. There should be no additional lines of output, nor any extra space at the end of the line.

### Improving the code

Concatenating a list of strings seems like something that people would want to do often. So, as you may suspect after the previous exercise, there is an in-built function to do this for you.

Comment out your old code, and beneath it add the following line:

```python
print(' '.join(strings))
```

Make sure it works by running your code.

When you push this new change to your repo, make sure that your pipeline is still "passed". The purpose of pipelines is to ensure that new changes to code do not break any existing behaviour. In general, if you do not have a "passed" pipeline for a lab task then you have not completed it satisfactorily and will lose marks.
