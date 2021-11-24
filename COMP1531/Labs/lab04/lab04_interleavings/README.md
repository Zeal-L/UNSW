## Lab04 - Exercise - Interleavings (3 points)

Write a function called `interleavings(a, b)`. Each string can be either empty or composed of unique characters. Additionally, when these two strings are concatenated together, the resulting string will also either be empty or composed of unique characters.

Your `interleavings` function should return a list containing all unique *interleavings* of the two strings in lexographically sorted order.

An interleaving of strings `a` and `b` is a string where:

* all the characters of `a` and `b` each appear once
* the original order of letters in `a` with respect to each other is preserved
* the original order of letters in `b` with respect to each other is preserved

Here are two examples:

```python
>>> interleavings('ab', 'cd')
['abcd', 'acbd', 'acdb', 'cabd', 'cadb', 'cdab']
```

```python
>>> interleavings('a', 'cd')
['acd', 'cad', 'cda']
```

#### Hints

* A second helper function may be useful in this question
* Recursion is your friend

Problem sourced from Grok Learning NCSS Challenge (Advanced), 2017.
