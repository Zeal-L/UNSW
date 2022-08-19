## Lab 03 - Core Exercise - Cars 🚗 

In this problem, we are going to continue the UML Diagram exercise from the tutorial. Your tutor will provide a pdf containing the diagram you worked on together.

> ℹ️ You will need to make a **Private** (set to Course Staff can view only) Blog Post on WebCMS for this activity. Put your answers to the questions inside it.

<details>
<summary>
Copy this template into your blog.
</summary>

```
Task 1

<Paste your highlighting screenshot here>

<List of requirements>

Task 2

<Document your design decisions here>

<Paste a picture of your UML diagram here>

Reflections

<your reflections here>
```

</details>

### Requirements Version 1

A Car has one or more engines and a producer. The producer is a manufacturing company who has a brand name.  Engines are produced by a manufacturer and have a speed. There are only two types of engines within UNSW's cars:

* **Thermal Engines**, which have a default max speed of 114, although they can be produced with a different max speed, and the max speed can change to any value between 100 and 250.
* **Electrical Engines**, which have a default max speed of 180. This is the speed at which they are produced, and the max speed can change to any value that is divisible by 6.

Cars are able to drive to a particular location `x`, `y`.

Since UNSW is a world-leader in technology innovation, they want you to be able to model the behaviour of Time Travelling for *any* vehicle, and to model a time travelling car. A vehicle that travels in time *stays in the same location* but travels to a `LocalDateTime`.

### Requirements Version 2

In addition to the above which you did in the tutorial, you will need to model the following:

1. The Car also has an owner. The owner is the official 'owner of the car' on paper, who has a name, address and can own many cars. 

2. There are two new types of engines:

* **Nuclear Engines**, which has a default max speed of 223; the engine can be produced with a different max speed and can change to any number that is prime. Nuclear engines also have a nuclear energy value between 1 and 10 and are able to propel at their nuclear energy value.
* **Solar Engine**, which has a default max speed of 90, and the max speed can change to anything below 150. This is the speed at which they are produced.

3. In the innovation space, UNSW wants you to model flying for any vehicle. Flying constitutes driving, except to a location `x`, `y`, `z`. They also want you to model the following vehicles specifically:

* Planes, which are able to fly and contain a list of passengers' names
* Flying Cars (note that flying cars can still drive normally)
* Time Travelling Flying Cars

**You do not need to write any code for this exercise.**

### Task 1 - Requirements Analysis

Take out a set of highlighters (virtual or real if you want to print the above spec out) and allocate a colour for each of the following:

* Entities / Objects
* Relationships
* Properties / fields / attributes
* Actions / functionality

Go through the specification and highlight the various information appropriately with your different colours. Make a note of any other key information described in the text using bold/italics/underline as needed.

Once you have done this take a screenshot / picture of your highlighting and put it into your blog post. 

Then, create your own **list of requirements** by grouping together relevant information into a list of bullet points. Some people find it helpful to cut and paste the highlighted text and assemble the list. Copy this into your blog post as well. 

### Task 2 - Modelling the Domain

Complete the UML diagram which models the domain. As you complete the diagram, write down your thought process and reasoning behind any **design decisions** you make in your blog post.

Think about the following design concepts:

* Abstraction
* Inheritance by extending classes
* Abstract classes
* Interfaces
* Has-a vs Is-a relationships (Composition vs Inheritance)

Your UML diagram will need to include:

* Getters and setters
* Constructors
* Aggregation/Composition relationships
* Cardinalities
* Inheritance/implementation relationships 

Submit your UML diagram in a file called `cars-design.pdf` in the root directory of this repository. Put a screenshot of your UML diagram in your blog post as well.

### Week 03 - Core Blogging - Reflect on Domain Modelling

Once you have completed your domain model take some time to reflect on your thinking and completion of the activity:
* Did you change your mind about your design at any point? How did this change come about?
* Any other things that you thought were interesting / challenging?

Your reflection for this activity only needs to be a sentence or two; your thought process and reasoning from Task 2 will be the bulk of your blog post.