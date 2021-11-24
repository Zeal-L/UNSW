## Lab07 - Exercise - Reduce (2 points)

Implement the `reduce` function in `reduce.py`.

The `reduce` function takes a function and a list and applies the function over the list:

`reduce(f, xs)` takes the first two values from the list `xs`, and uses it as the parameters to call the function `f`. It feeds the return value from the function `f` and the next value from the list back in to the function `f` and repeats until the list `xs` is empty. If the list only has one element then it returns the first element. If the list is empty then it returns `None`. The original list passed in should not be modified.

```bash
reduce(f, [1,2,3,4,5])                  -> f(f(f(f(1,2),3),4),5)
reduce(f, [])                           -> None
reduce(f, [1])                          -> 1

reduce(lambda x, y: x + y, [1,2,3,4,5]) -> 15
reduce(lambda x, y: x + y, 'abcdefg')   -> 'abcdefg'
reduce(lambda x, y: x * y, [1,2,3,4,5]) -> 120
```

Write pytests for your reduce function in `reduce_test.py` and ensure they have 100% *branch* coverage. Ensure your code is `pylint` compliant.
