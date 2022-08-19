## Lab 02 - Core Exercise - Hotel 🏨

> ℹ️ You will need to make a **Private** (set to Course Staff can view only) Blog Post on WebCMS for this activity. Put your answers to the questions inside it.

<details>
<summary>
Copy this template into your blog.
</summary>

```
Task 1

Q1: Why is this approach considered good design? What principles does it makes use of? 

<your answer here>

Q2: What is meant by the term "black-box"? How are the tests inside `BookingSystemTest` black-box?

<your answer here>

Task 2

Q3: What does this method do? What does it return, and what side effects does it have?

<your answer here>

Q4: In your opinion, which is better quality code, Code A or B? Justify your answer.

<your answer here>

Task 3

Q5: What are some code smells (features of the code that make it poor quality) present in this method?

<your answer here>

Task 4

Q6: Note down all of the code smells you can see.

<your answer here>

Q7: Reflect on your thought process, the steps you took to refactor and how you have improved the design of the system.

<your answer here>

Reflections

<your reflections here>
```

</details>

### Overview & Product Specification

Inside `src/hotel` there is some starter code for the backend to a hotel booking system. The system is designed to address the following requirements:

* There are three types of rooms:
    * Standard rooms;
    * Ensuite rooms; and
    * Penthouse rooms
* A Hotel has a series of rooms and a name.
* Rooms can be booked from a start date to an end date, and the client can specify which of the types of rooms they wish to book
* Each of the types rooms has their own custom welcome message.

### Task 1 - Architecture Analysis

Start by taking a look at the `BookingSystemController` class. You do not need to understand all of the code in it, some of the constructs such as Streams we will be learning about in later weeks. 

<img src="imgs/architecture.png" width="800"/>

The booking system is broadly speaking an **Abstract Data Type** - it is a system that contains information (data), has meaning (type) and functions as a **black-box** (is abstract). This means that the system can be used by different **ADT Clients** who can each create an instance of and use the system **without understanding how it is implemented under the hood**. For example in the diagram above, ADT Clients of the booking system could include the tests we have written, or an API layer which is using the `BookingSystemController`, or a Command Line Interface which acts as a wrapper around the controller.

**Q1: Why is this approach considered good design? Write the answer in your blog for this activity. In your answer, consider the terms abstraction, encapsulation and modularisation**. 

**Q2: What is meant by the term "black-box"? How are the tests inside `BookingSystemTest` black-box?**

In the proceeding tasks, you will be able to edit any of the classes inside the `hotel` package except for `BookingSystemController`. You should not need to edit it, though you can modify the internal mechanics of the class if you like without changing the external interface (public methods).

### Task 2 - Code Analysis

a. Look at the code inside the `Hotel` class. In particular, look at the `makeBooking` method.

```java
/**
 * Makes a booking in any available room with the given preferences.
 * 
 * @param arrival
 * @param departure
 * @param standard - does the client want a standard room?
 * @param ensuite - does the client want an ensuite room?
 * @param penthouse - does the client want a penthouse room?
 * @return If there were no available rooms for the given preferences, returns false.
 * Returns true if the booking was successful
 */
public boolean makeBooking(LocalDate arrival, LocalDate departure, boolean standard, 
                           boolean ensuite, boolean penthouse) {
    for (Room room : rooms) {
        if (roomDesired(room, standard, ensuite, penthouse) && room.book(arrival, departure) != null) {
            return true;
        }
    }

    return false;
}
```

**Q3: What does this method do? What does it return, and what side effects does it have? Write your answer in your blog.** 

b. In the `createRoom` method there are two ways of creating a new room. One has been commented out in the actual code.

<table>
<tr>
<th>Code A</th>
<th>Code B</th>
<tr>
<td>

```java
public void addRoom(String roomType) {
    Room room = null;

    switch (roomType) {
        case "standard":
            room = new StandardRoom(); break;
        case "ensuite":
            room = new EnsuiteRoom(); break;
        case "penthouse":
            room = new PenthouseRoom(); break;
    }

    rooms.add(room);
}
```

</td>
<td>

```java
public void addRoom(String roomType) {
    switch (roomType) {
        case "standard":
            rooms.add(new StandardRoom()); break;
        case "ensuite":
            rooms.add(new EnsuiteRoom()); break;
        case "penthouse":
            rooms.add(new PenthouseRoom()); break;
    } 
}
```

</tr>
</table>

**Q4: In your opinion, which is better quality code, Code A or B? Justify your answer.**

Once you have done this delete the other block of code in the method.

### Task 3 - Refactoring a Method

Consider the method `roomDesired` in the `Hotel` class.

```java
private boolean roomDesired(Room room, boolean standard, boolean ensuite, boolean penthouse) {
    if (room instanceof StandardRoom) {
        if (standard) return true;
        else return false;
    } else if (room instanceof EnsuiteRoom) {
        if (ensuite) return true;
        else return false;
    } else if (room instanceof PenthouseRoom) {
        if (penthouse) return true;
        else return false;
    } else {
        return false;
    }
}
```

**Q5: What are some code smells (features of the code that make it poor quality) present in this method?**

**Task**: Refactor the method so that it only contains one line of code.

Inside `BookingSystemTests` there is a subset of the tests called `RefactoringRegressionTests`. The tests are currently passing - you need to ensure that they stay passing. When refactoring code, it is important that the correctness of the system is maintained (i.e. the tests stay passing).

### Task 4 - Refactoring the Design

Consider the architecture of the system more broadly. The code currently uses an interface `Room`, and the three different types of rooms are modelled as `StandardRoom`, `EnsuiteRoom` and `PenthouseRoom` which all `implement` `Room`.

What do you notice? Recall concepts of code style from COMP1511 and basic Software Engineering Design Principles from COMP1531 - **DRY - Don't Repeat Yourself** and **KISS - Keep it Simple Stupid**. 

**Q6: Note down all of the code smells you can see in your blog**.

**Task**: Refactor the `Room` classes to remove the smells and improve the quality of the design. Make sure that the `RefactoringRegressionTests` remain passing.

**Q7: Once you have done the refactoring, in your blog reflect on your thought process, the steps you took to refactor and how you have improved the design of the system**.

<details>
<summary>
Here is a hint to help you if you are stuck. Try figuring it out on your own first! Look at the tutorial/lecture content for ideas. We want you to be able to put the puzzle pieces together yourself :) 

But if you still are stuck, then have a peek :)
</summary>

<br/>

Consider changing the inheritance structure in your refactoring.

<details>
<summary>

Here is another hint (a hint within a hint) in case you are still stuck, but **try and figure it out with the pieces you have first!**

</summary>

<br/>

Currently the code uses an `interface` - change it to use an `abstract class` instead.

</details>

</details>


### Task 5 - Overlaps

Well done, you've completed the refactoring! Now it's time to finish off the system. 

Complete the `overlaps` method inside the `Booking` class. `Task5OverlapsTests` will check your implementation is correct.

```java
/**
 * Checks whether two dates overlap
 * @param start
 * @param end
 */
public boolean overlaps(LocalDate start, LocalDate end) {
    return false;
}
```

### Task 6 - `toJSON`

Implement the `toJSON` method in all classes that contain its stub. `Task6JSONTests` will check your implementation is correct.

<details>
<summary>

Here is a hint if you are struggling with using JSON in Java. **Try googling it before looking at this hint as there is lots of documentation on the internet.**

</summary>

<br/>

Look at the `Task6JSONTests`. 

</details>

### Blog 02 - Reflect on the Hotel Lab

Well done on making it to the end! This was an extensive exercise. Finish up your answers to the questions, and **write a short reflection on the activity containing what you learned and any challenges you faced**. Once you have done this post your blog!!! (remember to set it to Course Staff can view only)

<img src="imgs/quote.jpg" width="800"/>
