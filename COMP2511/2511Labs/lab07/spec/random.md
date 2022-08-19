## Lab 07 - Core/Choice Exercise - The Art of Randomness 🎲

> ℹ️ You will need to make a **Private** (set to Course Staff can view only) Blog Post on WebCMS for this activity. Put your answers to the questions inside it.

Testing code that has an element of randomness is bit of a funny thing. When testing normal code, you will have a deterministic 1:1 mapping of inputs to outputs, i.e. for any given input, you know what the output will be and can assert that the actual output is what you expect. 

The good news is that in computers, there's no such thing as true randomness (though this is not completely true, and you can read [here](https://engineering.mit.edu/engage/ask-an-engineer/can-a-computer-generate-a-truly-random-number/) for more information). Computers generate *pseudo-random* or fake-random numbers that do the job of being random to us pretty well. This means that we can actually test functions where the result is determined by one of these psuedo-random algorithms. 

### Seeds

We can do this by using a common **seed** given to the java `Random` object in `java.util.Random`. Here is an example:

```java
Random rand1 = new Random(1);
Random rand2 = new Random(1);
assertEquals(rand1.nextInt(), rand2.nextInt());
```

The above assertion will always pass.

Using this knowledge, we can use the deterministic result of the `Random` object to write tests.

### Task

Inside `src/random`, in `Game.java` there are is an unimplemented functions named `battle`. This function should return `true` if the hero wins the battle and `false` if they lose. The chance of the hero winning is 0.5. 

There are two constructors for the class; one for testing where the `random` attribute is seeded with the given value, and a default constructor which uses the current time as the seed. The default constructor is for real usage (for example, the `main` method we have provided). 

When the `Random` object is constructed with a seed of `4`, the following values are the results first 8 calls to `.nextInt(100)`:

```
62 52 3 58 67 5 11 46
```

For `-4`:

```
39 13 98 5 43 89 20 23
```

For `0`:

```
60 48 29 47 15 53 91 61
```

* Write at least 2 unit tests for `battle` inside `GameTest.java` using seeds. 
* Once you have done this, implement the function.
* How would you write tests for `Game` with the default constructor that prove the `battle` function works as expected? Think about this and be prepared to answer during marking. Write your answer down in your blog post.

