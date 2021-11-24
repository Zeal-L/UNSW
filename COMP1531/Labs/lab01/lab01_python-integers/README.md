## Lab01 - Exercise - Integers (1 point)

Python lists are probably the most used data structure that comes out of the box with python. Assuming you are familiar with arrays in C, they are similar in that they are an ordered data structure supporting efficient random access. Unlike arrays, however, they are able to grow dynamically meaning their size does not need to be declared up front.

We will use a list to add up some integers in this exercise. (HINT: the python documentation is extensive and tells you how to use much of the built-in functionality. [https://docs.python.org/3.7/tutorial/datastructures.html](https://docs.python.org/3.7/tutorial/datastructures.html) )

**Steps:**

1. Open the `integers.py` file
2. Line 1 has declared a list of integers. You are required to add the number 6 to the list (using the `append` function) and then add all of the numbers up using a `for` loop and print out the result
3. Make the required edits to complete the above goal and run the `integers.py` in the same way you ran `hello.py`
4. At the bottom of the file add the line

    ```python
    print(sum(integers))
    ```

5. Note that the answers should be the same. This is an example of one of Python's inbuilt functions. It is important to remember that Python comes with many built-in functions for common operations. They should be favoured over "reinventing the wheel" and implementing them yourself.
