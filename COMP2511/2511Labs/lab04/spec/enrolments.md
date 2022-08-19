
## Lab 04 - Core Exercise - Enrolments 🛡️

> ℹ️ You will need to make a **Private** (set to Course Staff can view only) Blog Post on WebCMS for this activity. Put your answers to the questions inside it.

### Overview & Product Specification

Inside `src/unsw/enrolment` is a codebase that models a system with the following requirements:

* Students enrol in courses that are offered in particular terms
* Students receive grades (pass, fail, etc.) for courses in particular terms
* Courses may have pre-requisites (other courses) and must have credit point values
* For a student to enrol in a course, they must have passed all prerequisite courses

There is a simple integration test inside `test/EnrolmentTest.java`, which currently passes.

### Task 1 - Design Principles

> This task involves you making a series of refactoring changes to improve the quality of the code and design. Ensure the correctness of the system is maintained by keeping the tests passing. You can modify the tests slightly if necessary.

| Something important to note for this task is you will be asked to identify **code smells** and the **design problem**. These are not the same thing. For example, you could have some rotten food sitting in your cupboard - the smell of the food is how you detect that there is a problem; the problem is the rotten food itself. 💩 |
| --- |

#### Part A

Consider the following method inside `Enrolment.java`.

```java
public boolean hasPassedCourse() {
    if (grade == null) {
        return false;
    }

    return grade.getMark() >= 50 && grade.getGrade() != "FL" && grade.getGrade() != "UF";
}
```

**Q1: What is the code smell present in this snippet? What is the design problem causing the smell? Write your answer in your blog.**

**Task**: Refactor this method to remove the design problem and smell. You will need to edit another class as well in order to do this. In your blog, note down your refactoring steps and design decisions.

#### Part B

In the enrolments codebase, there is a violation of the Law of Demeter / Principle of Least Knowledge. 

**Q2: Find this code, and in your blog note down the code smells you detected which led you to your conclusion.**

**Task**: Refactor the code to remove the design problem and smell. In your blog, note down your refactoring steps and design decisions.

#### Part C

In the enrolments codebase, there is a violation of the Liskov Substitution Principle.

**Task**: Find and fix the violation, noting down how you found the problem and refactoring steps.

### Task 2 - Streams

Functional programming concepts allow us to make our code more clean and concise, and reduce traditional, rather verbose code into simple one-liners, such as the following:

<table>
<tr>
<th>
Procedural
</th>
<th>
Functional
</th>
</tr>
<tr>
<td>

```java
List<Integer> discountedPrices = new ArrayList<Integer>();
for (Integer item : prices) {
    if (item < 20) {
        discountedPrices.add(item / 2);
    } else {
        discountedPrices.add(item - 5);
    }
}
```

</td>
<td>

```java
List<Integer> discountedPrices = prices.stream()
                                       .map(item -> ((item < 20) ? (item / 2) : (item - 5)))
                                       .collect(Collectors.toList());
```

</td>
</tr>
</table>

**Task**: Improve the quality of the **code** in the enrolemnts codebase by rewriting instances of `for (X x : collection) { ... }` using Java streams and accompanying methods and lambdas. One example of this is provided in the starter code given in `studentsEnrolledInCourse`.

<details>
<summary>
Hint
</summary>

You may find some of the following Java stream methods useful:

* `anyMatch`
* `allMatch`
* `forEach`
* `filter`
* `map`
* `findFirst`

</details>

### Task 3 - Comparator

Complete the implementation of the `studentsEnrolledInCourse` function by sorting the list using a custom-defined comparator. Students should be sorted by:
* Their program; then
* The number of streams they are enrolled in, in ascending order; then
* Their name; then
* Their zID

You should start by writing a failing unit test in the `testComparator` method of `EnrolmentTest`.

Firstly use an anonymous class to implement the comparator.

Once you have done this, comment out your anonymous class and implement the sorting in one line of code. Compare the two approaches briefly in your blog.

### Week 04 - Core Blogging - Reflect on the Enrolments Lab

In a short paragraph, reflect on any challenges you faced and what you learned by completing this lab. Looking back on code you have written in the past, how has what you've learned improved your code and design quality?