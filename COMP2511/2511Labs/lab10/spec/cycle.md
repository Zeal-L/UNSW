## Lab 10 - Revision Exercise - Cycle

The class `Cycle` represents an ordered, infinitely repeating sequence of items of type E. Henceforth in this question, we denote a cycle as a finite sequence of elements separated by commas within angle brackets, which will be repeated infinitely in the denoted cycle. For example:

```
<1, 2, 3> represents the infinite-length cycle ..., 1, 2, 3, 1, 2, 3, ...
```

A Cycle is instantiated with a List of items of finite size, which will be repeated infinitely. This means that shifting the cycle to the left or right will still result in an equal cycle. For example, the following are equal cycles:

```
<1, 2, 3> is equal to <3, 1, 2>
<5, 6>    is equal to <6, 5, 6, 5, 6, 5, 6, 5>
```

Additionally, a cycle which can be obtained by "simplifying" another cycle is an equal cycle. A cycle is considered fully simplified when its internally stored finite-length list of elements is as short as possible, and repeating this internal list infinitely forms an equal cycle to the original cycle. For example, the following are equal cycles:

```
<1, 2, 1, 2> is equal to <1, 2>
<1, 2>       is equal to <1, 2, 1, 2>
<1, 2, 1, 2> is equal to <2, 1>
<2, 1>       is equal to <1, 2, 1, 2>
<1, 2, 1, 2> is equal to <1, 2, 1, 2, 1, 2> (since both are equal to <1, 2>)
<1, 2, 1, 2> is equal to <1, 2, 1, 2, 1, 2, 1, 2>
```

And so on...

An iterator generated for a Cycle should repeat infinitely if the Cycle is non-empty. If the cycle is empty, calling iterator.next() should throw a java.util.NoSuchElementException, and calling iterator.hasNext() should return false. If the cycle is non-empty, calling iterator.next() should return the next item in the cycle (wrapping around to the beginning if the end of the Cycle is reached), and calling iterator.hasNext() should return true. You will need to implement your own implementation of the java.util.Iterator interface and return an instance of this from your Cycle.iterator method:

https://docs.oracle.com/en/java/javase/11/docs/api/java.base/java/util/Iterator.html

Your task is to implement the following methods in the Cycle class:

* The iterator method
* The equals method 

You may find this question challenging. We recommend leaving this towards the end of the exam and to do it only if you have time.
As part of completing the iterator method above, you should also implement the methods marked as TODO in the file CycleIterator.java. For the equals method, you MUST ensure the contract of `Object.equals` is adhered to.

Hint: when comparing two Cycles to check if they are equal, you may wish to calculate a fully simplified finite-length sublist of each cycle, such that if this simplified sublist is repeated infinitely it forms a cycle equal to the cycle it was generated from. For example:

```
A fully simplified, finite-length sublist of the cycle <1, 2, 1, 2> is    [1, 2]
A fully simplified, finite-length sublist of the cycle <1, 2, 1, 2, 5> is [1, 2, 1, 2, 5]
```

You should read the provided file `TestCycle.java` to understand how Cycle objects are created and tested. Make sure that your solution successfully passes the tests in `TestCycle`. You should thoroughly test your solution for additional test cases - we will be using different test cases to test your submission.