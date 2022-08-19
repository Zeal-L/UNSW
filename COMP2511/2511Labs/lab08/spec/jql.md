## Lab 08 - Core Exercise - Java Query Language (JQL)

> ℹ️ You will need to make a **Private** (set to Course Staff can view only) Blog Post on WebCMS for this activity. Put your answers to the questions inside it.

| 💡 *To receive full marks in this exercise you do not need to complete all core parts*. We will assess you on your ability to understand the problem, design a solution and think critically as opposed to the number of tasks you completed. This all should be documented in your blog post. Set aside a 3 hours to work on the problem. Stop once you reach your allocated time and make sure to document how long you spent on each section. |
| --- |

<details>
<summary>
Copy this template into your blog.
</summary>

```
Task 1

Q1: Describe an example of where you have seen or used declarative programming concepts before that is *not* listed in the spec and briefly describe it in your blog. If you can't think of any, research into an example online and write about that instead.

As part of your answer, illustrate how using a declarative approach instead of an imperative approach has made your code more concise.

<your answer here>

Task 2 : <amount of time spent>

Task 3 : <amount of time spent>

Q2: Explain where and why the iterator invalidation occurs. You will need to put in breakpoints and debug the code in order to figure this out.

<your answer here>

Q3: This design isn't perfect as you may have guessed. What are some smells and design problems that you can see?

<your answer here>

Task 4 : <amount of time spent>

Task 5 : <amount of time spent>

Task 6 (Choice) : <amount of time spent>

<your design here, delete this if you didn't complete Task 6>

Task 7 : <amount of time spent>

Q4: What is the problem with the first pig's approach to synchronisation?

<your answer here>

Q5: What the problem with the second pig's approach to synchronisation?

<your answer here>

<your process for finding the answer + how your synchronisation works>

Reflections

What was the most challenging aspect of this lab? 
What was your biggest takeaway from the exercises?

<your reflections here>

```

</details>


This lab attempts to bring you through the thought process behind query styled language extensions (i.e. Streams in Java/LINQ in C#), and their relevance to modern technologies such as SQL.

The attempt is for this lab to be more educational than _hard_, so don't overcomplicate each of the sections.

### Task 0) Pre-reading

[Watch this video which gives an overview of the lab](https://www.youtube.com/watch?v=D9RxPP0lqqU) before you start.

### Task 1) Background: Declarative Programming & Query Languages 🔰

You've already dealt with a query language in this course. Java Streams!  An example is below that does the following;

1. Defines a user with 3 properties; isActive, userId, jobTitle.
2. Defines a some users
3. Then creates a stream that groups each active person by their job then prints out the job statistics
    - i.e. `{Business Analysts=1, CEO=1, Devs=2}` is the example output
    - Filter you would have seen previously, and is simply just removing all inactive users
    - Sorting by the group id just makes it so the jobs appear in alphabetical order
    - GroupingBy is probably a new thing for you, it allows you to change how your data is structured and in this case creates a mapping between each job and the count of each person
        - The first argument is what you are grouping by
        - The second argument in this case means it's going to use a LinkedHashMap to create the mapping structure.  This means it preserves the sorting order that was specified above.
        - The last argument means the value for each record will be the count.

```java
import java.util.*;
import java.util.function.*;
import java.util.stream.*;

public class User {
    private boolean isActive;
    private String userId;
    private String jobTitle;

    public User(boolean isActive, String userId, String jobTitle) {
        this.isActive = isActive;
        this.userId = userId;
        this.jobTitle = jobTitle;
    }

    public boolean isActive() {
        return isActive;
    }

    public String userId() {
        return userId;
    }

    public String jobTitle() {
        return jobTitle;
    }

    @Override
    public String toString() {
        return userId;
    }

    public static void main(String[] args) {
        List<User> users = new ArrayList<User>();
        users.add(new User(true, "A", "Devs"));
        users.add(new User(true, "B", "Devs"));
        users.add(new User(false, "C", "Testers"));
        users.add(new User(true, "D", "Business Analysts"));
        users.add(new User(true, "E", "CEO"));

        // {Business Analysts=1, CEO=1, Devs=2}
        System.out.println(
            users.stream()
            .filter(x -> x.isActive())
            .sorted(Comparator.comparing(User::groupId))
            .collect(Collectors.groupingBy(User::jobTitle, () -> new LinkedHashMap(), Collectors.counting())));
    }
}
```

This looks eerily similar to a more *declarative* language like SQL (purely as an example, you don't have to understand the following)

```sql
SELECT JobTitle, COUNT(1)
FROM Users
WHERE IsActive = 1
GROUP BY JobTitle
ORDER BY JobTitle ASC
```

- `select` is similar to `map`
- `where` is similar to `filter`

This is in contrast to the world of programming we are used to from C, traditional Python and Java - **imperative programming** where we write a *series of steps* to take us to the end state. **Declarative programming** on the other hand allows us to simply say "this is what we want" and *declare* the answer, as shown in the above example.

One more example of this you will have seen before is list comprehensions in python:

<table>
<tr>
<th>
Imperative
</th>
<th>
Declarative
</th>
</tr>
<td>

```python
evens = []
for x in range(100):
    if x % 2 == 0:
        evens.append(x)
```

</td>
<td>

```java
evens = [ x for x in range(100) if x % 2 == 0 ]
```

</tr>
</table>


Your task is to write your own stream classes to accomplish something similar to Java Streams - a "Java Query Language", or JQL for short.

**Q1: Describe an example of where you have seen or used declarative programming concepts before that is *not* listed above and briefly describe it in your blog. If you can't think of any, research into an example online and write about that instead.** 

**As part of your answer, illustrate how using a declarative approach instead of an imperative approach has made your code more concise.**

### Task 2) Generic Table 🏓

> For this entire lab you are prohibited from using any Java streams APIs. You can also presume that tables won't be modified during iteration.

We will start by looking at the `unsw/jql/v2` package. Currently, Tables can only consist of User records, as shown below.

```java
package unsw.stream;

import java.util.List;

public class Table {
    private List<User> records;

    public Table(List<User> records) {
        this.records = records;
    }

    public TableView toView() {
        return new SimpleTableView(records.iterator());
    }
}
```

**Task**: Parameterise the `Table` class on a generic argument so that it becomes `Table<E>` (make sure to name the generic argument `E`). This will require modifying other parts of the `v2` package as well. This should be mostly just changing generic arguments to Iterators/ArrayLists.

> Once you have completed this, uncomment the tests inside `JQLV2Tests` which should now compile.

### Task 3) Iterator Invalidation :radioactive_sign:

We'll come back to the `v2` package shortly, for now have a look at the `v1` package instead.

Inside `JQLV1Tests`, `testSkip` inside `Task3IteratorInvalidationTests` is failing, despite the fact that the functionality to skip records has already been implemented in `v1/decorator/SkipDecorator.java`. Here is the error message:

```
org.opentest4j.AssertionFailedError: iterable lengths differ, expected: <5> but was: <0>
```

Somewhere in the code the iterator being used to skip the records is being invalidated.

**Q2: Explain where and why the iterator invalidation occurs. You will need to put in breakpoints and debug the code in order to figure this out.**

To resolve the issue, we are going to need to modify the `SimpleTableView` class so that as well as storing the iterator to the records in the table, it will also need to store the records themselves.

**Task**: Modify the `SimpleTableView` class so that it stores a copy of the records as well as the iterator. You will need to update the records copy as the iterator is updated in order for the records to remain consistent with the state of the iterator. Once you have done this, use your updated code to resolve the bug and pass the tests.

**Q3: This design isn't perfect as you may have guessed. What are some smells and design problems that you can see?**

### Task 4) Select & Take: Object-Oriented Decorator 🎀

Inside `v1/decorator`, implement the `TakeDecorator` and `SelectDecorator` so that the `Task4TakeSelectTests` pass. The class constructors for each should be as follows:

```java
/**
 * Grab a subset of the table view
 * @param numberOfItems The number of items to take, the rest are ignored
*/
public TakeDecorator(TableView<E> inner, int numberOfItems)
```

<details>
<summary>

Hint for `take`

</summary>

The `take` functionality has already been implemented in `v2/SimpleTableView.java`, so you can have a look there as a reference.

</details>

```java
/**
 * Map a table view to another table view.
 * 
 * Each item/record is mapped through the provided selector.
 * 
 * An example would be `new SelectDecorator(view, (fruit) -> fruit.age()))`
*/
public SelectDecorator(TableView<E> inner, Function<E, R> selector);
```

For the `SelectDecorator` consider that the types of the input `inner` and output (`next` for iteration, and `toTable` for aggregation) will not necessarily be of the same type. You will need to modify the generic parameters of `OperationDecorator` and hence the other Decorators for this to work.

### Task 5) Select & Take: Functional Decorator 🎁

You might be now thinking that the type parameters on our Decorator classes are starting to become ugly - and you should follow your nose here (it's definitely a code smell). This implementation is struggling to adhere to the open-closed principle. Now we have two pieces of technical debt lingering in our `v1` implementation of the Decorator.

Moreover, for functionality which is relatively simple (select, take and skip) we seem to have quite a lot of code and classes. Perhaps there is a way we can make our code more concise - instead of implementing the functionality as seperate *classes* we could instead implement it as seperate *functions*. After all, semantically the functionality is all just operating on a `SimpleTableView` - so it would make sense for those functions to belong within that class. How can we preserve the wrapping of functionality that the Decorator Pattern provided us with though? The answer: **anonymous classes**.

The code inside `jql/v2` has started this re-implementation.

Firstly look inside `jql/v2/TableView.java` which you edited earlier when parameterising the table. You'll see that the functions are now part of the interface.

<details>

<summary>

Secondly, have a look at the implementation of `take` below and how it uses an anonymous class to wrap new functionality around the existing `SimpleTableView`.

</summary>


```java
@Override
public TableView take(int numberOfItems) {
    SimpleTableView parent = this;

    return new SimpleTableView() {
        private int itemsLeft = numberOfItems;

        @Override
        public boolean hasNext() {
            return itemsLeft > 0 && parent.hasNext();
        }

        @Override
        public User next() {
            if (hasNext()) {
                itemsLeft--;
                return parent.next();
            } else
                throw new NoSuchElementException();
        }
    };
}
```

</details>

This also allows us to improve the conciseness of the code using the decoration as well, since it turns from an object-layering frenzy into a nice chain-call, like we have seen with Java streams:

<table>
<tr>
<th>
Object-Oriented Decorator (v1)
</th>
<th>
Functional Decorator (v2)
</th>
</tr>
<tr>
<td>

```java
new TakeDecorator<User>(new SkipDecorator<User>(table.toView(), 2), 1)
```

</td>
<td>

```java
table.toView().skip(2).take(1)
```

</td>
</table>

### Task 6) Where (Choice) :interrobang:

This exercise is optional; come back to it later if you have time as it's an interesting problem.

One thing you will notice with the `select(x -> x.y).take(10)` is that it only processes the `select` function 10 times, even if there are 100 records in the table. This is because our implementation of the Decorator Pattern (both OO and functional) allows us to implement **[lazy evaluation](https://en.wikipedia.org/wiki/Lazy_evaluation#Java)**, which is a big idea in the world of Functional Programming. We won't go into it too deeply here, but it essentially the idea that we want to only do work when we have to - if we only take 10 records, we only process the `select` 10 times.

This approach works well for functions where we don't need to know what comes next. But what about functions where what comes next is important?

This task is to implement the `where` function inside `v2/SimpleTableView.java`. You will need to think about this one, since the `hasNext` iterator method can't simply palm it off to the parent. Your iterator will need to 'look into the future' so to speak, but consider (a) the fact we want the iterator to be as lazy as possible (i.e. going throught all the remaining records, pre-filtering and storing them in the iterator isn't allowed), and (b) the fact that you want to avoid what we came across in Task 3) where the iterator was invalidated prematurely because we wanted to look ahead. Have a go yourself first, and there's a hint if you are stuck.

<details>
<summary>
Hint
</summary>

Some form of caching will help you here, where you have two members inside the anonymous class:

* `cached`, of type `E`
* `hasNextCached` of type `boolean`

</details>

Once you have completed this task explain how your solution is designed in your blog post.

### Task 7) Parallelism 🫖

In the starter code, we have implemented the `reduce` function for you. Currently our reduce function just operates on one item at a time, we want to be fancier here and operate on multiple at the same time!  Parallelism/Threading can help us here.  `parallelReduce` will operate on the stream from multiple threads at the same time!  However, iterators aren't thread-safe and require synchronisation to ensure you don't cause data races and other sorts of threading issues.  Effectively, every thread will be using the same iterator allowing it to iterate through multiple items at the same time.

Think about what happens in the following instance when there are multiple threads involved:

```java
if (iterator.hasNext()) {
    // can anything occur between above
    // and the line below that means it's no longer
    // valid to call `next`, causing an exception to be thrown?
    iterator.next();
}
```

If you run `testParallelReduce` a few times, you might notice that every so often it fails - this is what we call a **flaky test**.

`parallelReduce` is already written for you and you don't have to modify it.  The problem however, is that your reduce function most likely is not thread-safe, so you need to figure out a way to synchronise it.

Two little pigs tried doing this already and have kindly handed you their attempts at synchronisation for you to analyse.

Here is the initial code inside `SimpleTableView.java`:

```java
@Override
public <R> R reduce(BiFunction<R, User, R> reducer, R initial) {
    R cur = initial;

    /* Following is okay but not threadsafe */
    for (var val : this) {
        cur = reducer.apply(cur, val);
    }

    return cur;
}
```

Here is the first little pig's attempt to synchronise the reduction, instead of using straw however they tried this:

```java
@Override
public <R> R reduce(BiFunction<R, User, R> reducer, R initial) {
    R cur = initial;

    for (var val : this) {
        synchronized(this) {
            cur = reducer.apply(cur, val);
        }
    }

    return cur;
}
```

**Q4: What is the problem with the first pig's approach to synchronisation?**

Here is the second little pig's attempt to synchronise the reduction, instead of using sticks they tried this:

```java
@Override
public <R> R reduce(BiFunction<R, User, R> reducer, R initial) {
    R cur = initial;

    synchronized(this) {
        for (var val : this) {
                cur = reducer.apply(cur, val);
            }
        }
    }

    return cur;
}
```

**Q5: What the problem with the second pig's approach to synchronisation?**

If we run `stressTestParallelReduce` with either of those synchronisation methods, it will take about 100 seconds.

**Task**: Add synchronisation so the function so that `testParallelReduce` passes consistently, and that, unlike the two little pigs' attempts, `stressTestParallelReduce` runs in under 10 seconds.

Once you have completed the task write down your process for finding the answer, and how your synchronisation works in your blog post.

### Week 08 - Core Blogging - Reflect on the JQL Lab

Well done on completing the lab, whether you completed all the tasks or not. In your blog post, answer the following questions.

* What was the most challenging aspect of this lab? 
* What was your biggest takeaway from the exercises?
