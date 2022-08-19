## Lab 10 - Core Exercise - A Visiting Calculator ⏳

In Tutorial 07, we created a simple calculator using the Composite Pattern. That was all very well, but if you recall we had to construct the entire expression ourselves using objects, such as the following:

```java
// (1 + ((2 * 3) / 4)) - 5
Expression expr = new SubtractExpression(
                    new AddExpression(
                        new ModulusExpression(
                            new MultiplyExpression(new ValueExpression(2), new ValueExpression(3)), 
                            new ValueExpression(4)), 
                        new ValueExpression(1)), 
                    new ValueExpression(5));
```

This isn't currently very helpful if we wanted to just take in the expression `1 + 2 * 3 / 4 - 5` and manipulate, print or compute it, which is what we would need to do if we were going to make a real calculator application. This problem is known as **parsing**, which is [an interesting problem](https://en.wikipedia.org/wiki/Parsing) but outside the scope of the course.

Inside `unsw/calculator/model/tree` is some legacy code that uses the Composite Pattern to implement a tree, and will parse a string such as `"1 + 2 * 3 / 4 - 5"`  to construct the expression tree. In this exercise, we want to write code which prints the tree in various notations and evaluates the tree.

If we were building the model from scratch, we would probably just use the Composite Pattern. However, in many legacy codebases you may come across the code will be too complex and/or brittle to simply rewrite or add to easily, and you will instead have to build new functionality around existing code. To do this, we will use the Visitor Pattern.

### Task 1) Visitor Pattern

Use the Visitor Pattern to enable three operations on the Expression Tree:

* Print the Tree using [**infix notation**](https://en.wikipedia.org/wiki/Infix_notation). This is the commonly used notation for articulating arithmetic expressions. Given the above example, the expression in infix notation is `1 + 2 * 3 / 4 - 5`.
* Print the Tree using **postfix notation**, also known as [Reverse Polish Notation](https://en.wikipedia.org/wiki/Reverse_Polish_notation). Postfix Notation prints each of the operands and *then* the operator. For example `3 + 4` would be expressed as `3 4 +`. The above example would be expressed as `1 2 3 * 4 / + 5 -`.
* Evaluates the expression.

Inside `Visitor.java` we have provided you with an interface with two methods: `visitBinaryOperatorNode` and `visitNumericNode`. You will need to:
* Implement these methods in the classes `InFixPrintVisitor`, `PostFixPrintVisitor` and `EvaluatorVisitor` respectively;
* Modify `TreeNode` as needed to ensure that any class that extends/implements it must implement an `accept` method;
* Add an `acceptLeft` and an `acceptRight` method to `BinaryOperatorNode` to allow for the composite accepting of visitors.
* The starter code uses the Composite Pattern for the Infix printing operation to help you out, so you should remove that as well.
* In addition to the above, you also need modify the parsing code to support the modulus operator (`%`) in expressions.

We have provided you with some very basic tests inside `test/calculatorVisitorTest`. They are currently commented out as they don't compile. These tests must pass **without being changed** as our automarking will rely on the same class and method prototypes. You should write some additional tests to ensure your solution passes our autotests.

**We will be testing the contents of `stdout` to check your Infix and Postfix visitors (see the provided tests for an example), so please make sure you remove all your debugging print statements before submitting.**

<details>
<summary>Hint</summary>

In `EvaluatorVisitor`, you may wish to make use of a data structure to help you evaluate the expression.

</details>


### Task 2) Adapter Pattern (Choice) 🔌

This exercise follows on from the previous exercise. This exercise is completely optional. The Adapter Pattern is no longer core content in the course, but if you are interested in learning the theory [you can watch this previous lecture here (15 minutes)](https://web.microsoftstream.com/video/61ffccd3-8196-4ecb-8aa6-9aa5e26b667a?st=5533).

Inside `calculator/view`, there is some frontend code which renders an interface for a simple calculator. Now that we have completed the backend (model), we need to put the two together to create a working app. However, we have the problem that the interfaces between the view and the model are not compatible.

At the moment, there is a method inside the `CalculatorInterface` class `getEvaluator()`, which returns a `DummyEvaluator` object. This method is the point of contact between the backend and frontend - where the frontend can pass the backend an expression to compute and receive the result. Have a look at where this method is called and see how the frontend code works.

The `DummyEvaluator` which `implements Evaluator` has a method which returns `0`, which explains why when you run the application, enter an expression and press `=`, it spits out `0`. 

Your task is to use the Adapter Pattern to connect the backend and frontend. Complete `EvaluatorAdapter` which is of type `Evaluator` and computes a given expression using your code from the previous exercise.

We have provided some tests for you inside `test/calculatorAdapterTest`. These tests must pass **without being changed** as our automarking will rely on the same class and method prototypes. You will also be able to tell that the code is working via a Usability Test (run the `main` method in `CalculatorInterface` and test that the application works as it should).

Note that you will need to write very little code to solve this problem.