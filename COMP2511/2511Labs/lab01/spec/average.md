## Lab 01 - Core Exercise - Average 🔢

A class is similar to a struct in the C language in that it stores related data in fields, where the fields can be different types.

1. Open the file `src/average/Average.java`. You will find a class named Average.
2. This class defines a method `computeAverage()` that takes in an array of integers and returns the average of this numbers.  You are required to implement this method.

   * To complete this task, you need to compute the sum of the numbers and the total number of elements;
   * Use a `for` loop to traverse the list of numbers and compute the sum of the numberl
   * Use `nums.length` to get the length of the array, after the sum has been computed.

3. Next, define a `main()` method.

    **Note**: Every Java application needs one class with a `main()` method. This class is the entry point for the Java application and is the class name passed to the `java`  command to run the application. The interpreter executes the code in the `main()` method when the program starts, and is the point from which all other classes and corresponding methods are invoked. VSCode will recognise the `main` method and provide you with a "Run" button to run the code if you have the correct extensions installed.

4. Inside the `main()` method, initialise an array of the numbers 1 - 6 (integers) and invoke the method `computeAverage()`, passing it as an argument.

    **Hint**: `computeAverage()` is an instance method, so you will need to create an instance of the class Average and invoke the method on this instance.

5. Assign the result of this method to a variable and print the variable in the format: `The average is {average}`.

The pipeline for this repository will run a simple test on your code to check that it works as expected. You can run the tests yourself locally using `bash tests.sh`, though this will run tests for all exercises in the lab unless you modify it.

