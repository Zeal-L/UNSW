# COMP2511 22T2 Sample Exam

Please read the [COMP2511 Exam Information Page](https://webcms3.cse.unsw.edu.au/COMP2511/22T2/resources/75511) page for all information on the final exam.

DO NOT answer all questions.

The exam consists of three sections:
* Short Answer (25 marks)
    * Answer all of Q1 - Q6 core questions (19 marks)
    * Answer **two** out of **four** choice questions Q7 - Q10 (6 marks)
* Extended Answer (10 marks)
    * Answer Q12 (10 marks)
* Design & Programming
    * Question 13
        * Answer all of core parts a, b, c, d (35 marks)
        * Answer none out of none choice parts (0 marks)
    * Question 14
        * Answer all of core parts a, b, c, d (30 marks)
        * Answer none out of none choice parts (0 marks) 

## Section 1: Short Answer (25 marks)

| You must answer **six** out of the following six core questions. |
| ---------------------------------------------------------------- |

### Question 1 (2 marks)

Is the following an example of aggregation or composition? Explain why.

> An online call contains breakout rooms.

Write your answer inside `q1.txt`.

### Question 2 (3 marks)

Reflecting on the Software Engineering practices followed in your project, which of the following would you recommend **against** when completing the design and development of a similar software system? Briefly justify the options you have chosen (you do not need to justify the options you have not chosen).

<ol type="a">
    <li>Planning out an overview of the domain model at the beginning of the project</li>
    <li>Writing the entire UML diagram before writing any code</li>
    <li>Designing components of the system in small cycles/iterations of development</li>
    <li>Waiting until the prototype is perfect before testing the software</li>
    <li>No-one who practices Agile uses Object-Oriented Programming</li>
</ol>

Write your answer inside `q2.txt`.

### Question 3 (3 marks)

```java
class Animal {
    public String noise() {
        return "I make a noise";
    }
}

class Dog extends Animal {
    @Override
    public String noise() {
        return "Woof woof";
    }
}

class App {
    public static void main(String[] args) {
        Dog dog = new Dog();
        Animal animal = dog;
        System.out.println(animal.noise());
    }
}
```

What will the above program print? With reference to concepts surrounding dynamic polymorphism, explain your answer.

Write your answer inside `q3.txt`.

### Question 4 (4 marks)

Consider the following code:

```java
public class Flight {
    /*
    @precondition age >= 0, name does not contain any spaces
    @postcondition The flight is booked
    */
    boolean book(int age, String name) {
        // ...
    }
}

public class GoldFlight extends Flight {
    /*
    @precondition age >= 50, name does not contain any spaces
    @postcondition The flight is booked
    */
    @Override
    boolean book(int age, String name) {
        // ...
    }
}
```

With reference to Design by Contract and the Liskov Substitution Principle, explain why the inheritance here is invalid.

Write your answer inside `q4.txt`.

### Question 5 (4 marks)

Identify the code smells present in the following pieces of code, and how you would resolve the smells and/or any underlying design problems causing the smell.

Write your answer inside `q5.txt`.

#### Part A (2 marks)

Scenario 1: Dungeonmania project

```java
public List<Bomb> getBombs() {
    List<Bomb> bombs = new ArrayList<>();
    for (Entity entity : entities) {
        if (entity.getType().equals("bomb")) {
            bombs.add((Bomb) entity);
        }
    }
    return bombs;
}

public void bombPlaced(Item item) {
    if (item != null) {
    }
    if (!(item instanceof Bomb)) {
        return;
    }
    ((Bomb) item).placeBomb();
}

public void explodeBomb() {
    for (Bomb bomb : getBombs()) {
        bomb.explodeBomb();
    }
}

public List<FloorSwitch> getFloorSwitches() {
    List<FloorSwitch> floorSwitches = new ArrayList<>();
    for (Entity entity : entities) {
        if (entity.getType().equals("switch")) {
            floorSwitches.add((FloorSwitch) entity);

        }
    }
    return floorSwitches;
}

public List<Boulder> getBoulders() {
    List<Boulder> boulders = new ArrayList<>();
    for (Entity entity : entities) {
        if (entity.getType().equals("boulder")) {
            boulders.add((Boulder) entity);
        }
    }
    return boulders;
}
```

#### Part B (2 marks)

Scenario 2: Blackout assignment

```java
for (FileTransfer ft : fileTransfers) {
    if (ft.getFromEntity().equals(e) || ft.getToEntity().equals(e)) {
        filesMap.put(ft.getFile().getFileName(), new FileInfoResponse(ft.getFile().getFileName(), ft.getFile().getContent().substring(0, ft.getBytesIn()), ft.getBytesTotal(), false));
    }
}
```

### Question 6 (3 marks)

Suppose that as part of "Milestone 4" of the project that some new requirements have been introduced which require you to incorporate a series of new entities into the game. There are four new types of entities:

* Possessor bird;
* Venemous cockroach;
* Potato gnome; and
* Phoneix.

Each of these new entities can be produced as a creature of either fire, water, earth or air.

Select the most suitable creational Design Pattern. In answering, justify your choice by describing the mapping of this domain to the key characteristics of your chosen Design Pattern.

Write your answer inside `q6.txt`.

| You must answer **two** out of the following **four** choice questions. |
| ----------------------------------------------------------------------- |


### Question 7 (3 marks)

A user bought an application that reads data in JSON format, and displays results on a web page. Later, the user realised that one of their data sources is in XML format. Unfortunately, the user does not have access to the source code of the application, so it is not possible to change the application. 

Give the most appropriate design pattern for this situation. In answering, justify your choice by describing the mapping of this domain to the key characteristics of your chosen Design Pattern. 

Write your answer inside `q7.txt`.

### Question 8 (3 marks)

UNSW has asked you to build a web-based system where residential students can select their rooms for a new year. However, they are aware that when this system is built and deployed that as soon as the ability to select rooms is activated, residents will be rushing to select the rooms on the highest floors and with the best views. This may result in multiple people selecting the same room at the exact same time, corrupting data or causing logic errors. How would you design your web server to avoid this issue?

Write your answer inside `q8.txt`.

| :information_source: Stop here if you've answered two out of two choice questions already!  |
| ----------------------------------------------------------------------------------- |

### Question 9 (3 marks)

Consider the following code:

```java
class A<E> {
    protected int x = 0;

    public ArrayList<E> foo(String bar) {
        // …
    }
}

class B<E> extends A<E> {
    @Override
    public List<E> foo(String bar) {
        // …
    }
}
```

<ol type="a">
    <li>Explain, with reference to concepts surrounding encapsulation <b>one</b> problematic feature of the code. (1 mark)</li>
    <li>Which of the following statements is true? Justify your answer. (2 marks)
        <ol type="i">
            <li>The code will not compile as the inheritance breaks covariance</li>
            <li>The code will not compile as the inheritance breaks contravariance</li>
            <li>The code will not compile as generic types cannot be inherited</li>
            <li>The code will not compile as the generic type cannot be accessed from the child class</li>
            <li>The code will not compile, but for none of the above reasons</li>
            <li>The code will compile</li>
            <li>None of the above.</li>
        </ul>
    </li>
</ol>


Write your answer inside `q9.txt`.

### Question 10 (3 marks)

```java
public class GameOfLife {

    private BooleanProperty[][] cells;

    public GameOfLife() {
        cells = new BooleanProperty[10][10];
        for (int x = 0; x < 10; x++) {
            for (int y = 0; y < 10; y++) {
                cells[x][y] = new SimpleBooleanProperty();
            }
        }
    }

    public void ensureAlive(int x, int y) {
        cells[x][y].set(true);
    }

    public void ensureDead(int x, int y) {
        cells[x][y].set(false);
    }

    public boolean isAlive(int x, int y) {
        return cells[x][y].get();
    }
```

<ol type="a">
    <li>Identify one code smell in this program. (1 mark)</li>
    <li>Identify and explain the most pertinent (problematic) design smell in this program. (2 marks)</li>
</ol>

(This is an old exam question, here is information on what a [BooleanProperty](https://docs.oracle.com/javase/10/docs/api/javafx/beans/property/BooleanProperty.html) is).

Write your answer inside `q10.txt`.

## Section 2: Extended Answer (10 marks)

### Question 12 (10 marks)

Consider an airline booking system with the following requirements.

-   Passengers have schedules that involve at least one and maybe several flights.
-   Each flight has a departure date/time and an arrival date/time.
-   Flights are identified by a name (e.g. QF1) that may be repeated for different days/times.
-   Flights have a number of seats in several sections: first, business and economy class.
-   Each flight in each passenger's schedule includes the class of seat for that flight.
-   Each flight has a seat allocated for each of its passengers
-   The seat allocated to a passenger on a flight must match the seat class in the schedule. Passengers may book, cancel or update flights and seat allocations in their schedule.

Model the domain for the above requirements to form the basis of a potential software solution. Your answer should include:

* Interfaces
* Class Signatures, including inheritance relationships where appropriate
* Method Signatures
* Key Fields and relationships, including aggregations, compositions and cardinalities between entities

**You do not need to implement any of these classes/methods, you are simply providing the prototypes / stubs**. Any design decisions that you feel need justifying you can do so as a comment / JavaDoc in the respective file

An interface for the entire system has been provided to you in `src/main/java/q12/AirlineBookingSystemController.java`. You can modify these methods prototypes if you like, though you shouldn't need to.

There is a *lot* of undefined behaviour about this system, which is intentional. You can make as many assumptions as you need, so long as they don't reduce the scope of the specification. 

You will be assessed on:
* Modelling of Entities (3 marks)
* Inheritance & Interface Design (2 marks)
* Aggregations, Compositions and Cardinalities (3 marks)
* Modelling of Functionality (2 marks)

## Section 3: Design & Programming (65 marks)

In the real exam there will be a series of core parts to each question which you must answer, and a series of choice parts where you only need to answer a certain number out of the available parts.

### Question 13 (35 marks)

Typically, in commercial programs, we want to carry out actions only when a set of rules are true. As a shorthand, these are called business rules.

Let's assume we have the following operators and variables available:

Operators:

* Group operators (AND, OR).
* Comparison operators (NOT BLANK, IS GREATER THAN).
* Variables:

Is named LOOKUP. Constant values are labelled as simply just CONSTANT

* for example: "email", "phoneNumber", "mark", "responses", "invites", etc.
* variables can be one of the following types: Double, String.
* variables are looked up using a `Map<String, Object>` a link to the Javadoc's for Map is below. If the Map doesn't contain the variable, its value is null.

https://docs.oracle.com/javase/8/docs/api/java/util/Map.html

Possible business rules could be as simple as below:

The following is true if "email" variable is not blank (blank meaning that it consists purely of whitespace, is empty string, or is null), or "phoneNumber" is not blank.

```javascript
{
  "Operator": "OR",
  "Args": [
    {
      "Operator": "NOT BLANK",
      "Arg": {
        "Operator": "LOOKUP",
        "Arg": "email"
      }
    },
    {
      "Operator": "NOT BLANK",
      "Arg": {
        "Operator": "LOOKUP",
        "Arg": "phoneNumber"
      }
    }
  ]
}
```

The following is true if "responses" variable is greater than 2 and either "email" is not blank or "phoneNumber" is not blank.

```javascript
{
  "Operator": "AND",
  "Args": [
    {
      "Operator": "GREATER THAN",
      "Args": [
        {
          "Operator": "LOOKUP",
          "Arg": "responses"
        },
        {
          "Operator": "CONSTANT",
          "Arg": 2
        }
      ]
    },
    {
      "Operator": "OR",
      "Args": [
        {
          "Operator": "NOT BLANK",
          "Arg": {
            "Operator": "LOOKUP",
            "Arg": "email"
          }
        },
        {
          "Operator": "NOT BLANK",
          "Arg": {
            "Operator": "LOOKUP",
            "Arg": "phoneNumber"
          }
        }
      ]
    }
  ]
}
```

Business Rules always evaluate to a boolean value. For simplicity, we also only support very few operators in this example (the ones stated above). Furthermore, you can presume all constants are numeric (doubles).

All transformations/groups/operator's behaviour is explained in detail below.

<table>
<tr>
<th>Operator</th>
<th>Description</th>
</tr>
<tr>
<td>

`GREATER_THAN`

</td>
<td>

Given A, and B are either integers or doubles evalutes to true if A > B else false.

Should throw `BusinessRuleException("Both arguments have to be numeric")`
if either A or B isn't an integer or a double or if B isn't supplied.

</td>
</tr>
<td>

`IS_NOT_BLANK`

</td>
<td>

Is a unary operator returns false if the argument given is either null or a string consisting purely of spaces (or is empty) otherwise it returns true.

Hint: `string.isBlank()` will tell you if a string is empty/consists purely of spaces.

If the type is an integer/boolean/double it should always return true.

Ignores second argument if supplied.

</td>
</tr>
<tr>
<td>

`AND`

</td>
<td>
Evaluates the two business rules supplied and if both are true evaluates to true else it evaluates to false.
</td>
</tr>
<tr>
<td>

`OR`

</td>
<td>

Evaluates the two business rules supplied and if either are true evaluates to true else it evaluates to false.

</td>
</tr>
</table>

Your task is to design a solution that allows a user to create arbitrary rules as shown above. You must design your solution using one or more of the design patterns discussed in the course such that it could be easily extended (for additional operators)

#### a) Business Rule Evaluation (15 marks)

You have been provided with the following interface inside `BusinessRule.java`:

```java
public interface BusinessRule {
    public boolean evaluate(Map<String, Object> values);
}
```

Using an appropriate Design Pattern, model a solution that allows for the creation of the arbitrary rules as shown above. You must design your solution such that it could be easily extended (e.g. for additional operators).

Note down your chosen Design Pattern and any other important design decisions inside `q13.txt`.

You will be assessed on the following:
* Correctness (7 marks)
* Design (8 marks)

#### b) Business Rule Generation (10 marks)

Inside `BusinessRuleMain.java`, implement the method:

```java
public static BusinessRule generateRule(String inputBusinessRule) 
```

In your solution, use an appropriate creational design pattern.

You can use either gson or org.json (both libraries we've provided throughout the term) to implement your solution. You must obey the following; - JSON data should be extracted into classes and you should not store any json objects.

Once you have completed Part A and Part B, the provided integration test should pass.

Note down your chosen Design Pattern and any other important design decisions inside `q13.txt`.

You will be assessed on the following:
* Correctness (4 marks)
* Design (6 marks)

#### c) Baseline Modification (5 marks)

In many cases, the constant values in business rules serve as some form of "baseline" value, where the constant is indicative of a certain threshold (e.g. number of units sold). As times change so do these baselines, but instead of having to manually update them individually we want to be able to, given a single Business Rule **multiply** all constant values in that rule by a certain factor.

For instance, in the above example, if we updated the baseline with a factor of 2 the updated constant value would be:

```java
{
    "Operator": "CONSTANT",
    "Arg": 4
}
```

Add the following method to your `BusinessRule` which implements this functionality.

```java
public void updateBaseline(Integer factor)
```

Use an appropriate design pattern in your solution, noting it and any other important design decisions down inside `q13.txt`.

You can change the inheritance structure where needed, so long as the given integration test still passes.

You will be assessed on the following:
* Correctness (2 marks)
* Design (3 marks)

#### d) `toJson` (5 marks)

Your business rules need to be able to be converted back to JSON, as well as reading from the JSON file initially.

Add the following method to your `BusinessRule` which implements this functionality.

```java
public JSONObject toJSON(Integer factor)
```

Note down any important design decisions down inside `q13.txt`.

You will be assessed on the following:
* Correctness (2 marks)
* Design (3 marks)

### Question 14 (30 marks)

In 2022 COMP2511 has a project called "WasteBook", where students are required to create a miniature social media platform. One of the groups has produced a very basic prototype that accomodates for the following requirements:

- Each member has an ID, which can be of any comparable type depending on how the network is created
- A member can be added to the social network
- A member can 'follow' another member in the network. A user cannot follow themselves.
- If two people are following each other, they are classified as "friends"
- The **popularity** of a user is how many other users are following them

#### a) Code and Design Smells (5 marks)

Inside the `q14` there are two files, `Person.java` and `WasteBookController.java` that model the group's current system. Analyse the existing solutiion, and inside `q14.txt`, list all the design and code smells the code contains.

#### b) Refactoring (12 marks)

The code currently passes all of the given tests inside `WasteBookTestBaseline.java`. After your refactoring, the code should still pass the tests unchanged, maintaining the behaviour of the system.

Refactor the code to remove the smells, and in doing so make the code more extendible. Explain your refactoring steps inside `q9.txt`. For this part of the question you may, but **are not required to make use of a Design Pattern discussed in the course**. You simply need to improve the quality of the existing code.

You will be assessed in this question on your refactoring design decisions and maintaining the correctness of the system.

#### c) Iterator Updating (7 marks)

Currently, the `NetworkIterator<P>` class is a benign abstraction (a wrapper that provides no functionality) around an `Iterator<P>`. The iterator can be created via the `getIterator` method of the controller, which takes in a parameter the order of the network members should be iterated over (`"popularity"` or `"friends"`).

Additionally, when a new member is added to the network the iterator is **invalidated** (no longer up to date) as the object it was iterating over has been modified. The iterator does not remain up to date when new members are added.

Modify the `next` method so that it returns the person in the network with the highest rank according to the given comparison method which has not already been traversed, and remains up-to-date with new members added to the network and new connections made between members of the network. 

**You are required to cache (store a copy) of the network members inside the iterator for performance.** You do not need to store a copy of every member, just the data structure containing the members itself.

For example:

<table>

<tr>
<th>Current Iterator</th><th>Required Iterator</th>
</tr>
<tr>
<td>

```java
// * Romeo has popularity 3
// * Hamish has popularity 5
// * Evanlyn has popularity 6
NetworkIterator iter = controller.getIterator("popularity");
iter.next(); // Evanlyn
iter.next(); // Hamish
controller.addPersonToNetwork("Darcy");
// Darcy is given popularity 4
iter.next(); // Romeo
```

</td>
<td>

```java
// * Romeo has popularity 3
// * Hamish has popularity 5
// * Evanlyn has popularity 6
NetworkIterator iter = controller.getIterator("popularity");
iter.next(); // Evanlyn
iter.next(); // Hamish
controller.addPersonToNetwork("Darcy");
// Darcy is given popularity 4
iter.next(); // Darcy, as the iterator has updated
iter.next(); // Romeo
```

</td>
</tr>
</table>

There is a simple test for this question inside `WasteBookTestExtra.java`.

**Make a note of any refactoring steps and/or Design Patterns discussed in the course that you use in `q14.txt`.**

The breakdown of marks for this question is as follows:
* Design (4 marks)
* Correctness (3 marks)

#### d) Switching Comparison Method (6 marks)

To ensure the software can scale well, the application that allows for searching users by popularity or number of friends needs to be able to change the comparison method mid-iteration for remaining members to be traversed, rather than having to start from the beginning. This feature requires us to make some unique changes to our iterator.

Inside the controller, complete the method:

```java
public void switchIteratorComparisonMethod(NetworkIterator<P> iter, String orderBy);
```

This method takes in an existing `NetworkIterator` created using `getIterator` and changes the method of comparison used to determine the ordering of the elements mid-iteration. 

The possible comparison methods are the two previous ones:
* `popularity`
* `friends`

The `next` method of the iterator should return the person in the network with the highest rank according to the up-to-date comparison method which has not already been traversed.

For example:

```java
// * Nathan has popularity 5 and 2 friends
// * Evanlyn has popularity 10 and 8 friends
// * Darcy has popularity 9 and 6 friends
// * Hamish has popularity 7 and 7 friends
NetworkIterator<String> iter = controller.getIterator("popularity");
iter.next() // Evanlyn
controller.switchIteratorComparisonMethod(iter, "friends");
iter.next() // Hamish, not Darcy as we are comparing by # friends, not popularity now
iter.next() // Darcy
iter.next() // Nathan
```

There are no tests provided for this question. You should, but are not required to write your own tests for this question inside `WasteBookTestExtra.java`.

**Make a note of any refactoring steps and/or Design Patterns discussed in the course that you use in `q4.txt`.**

The breakdown of marks for this question is as follows:
* Design (3 marks)
* Correctness (3 marks)

## End of Exam
