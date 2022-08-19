## Lab 10 - Revision Exercise - Friends

In 2022 COMP2511 has a project called "WasteBook", where students are required to create a miniature social media platform. One of the groups has produced a very basic prototype that accomodates for the following requirements:

- Each member has an ID, which can be of any comparable type depending on how the network is created
- A member can be added to the social network
- A member can 'follow' another member in the network. A user cannot follow themselves.
- If two people are following each other, they are classified as "friends"
- The **popularity** of a user is how many other users are following them

#### a) Code and Design Smells (5 marks)

Inside the `friends` package there are two files, `Person.java` and `WasteBookController.java` that model the group's current system. Analyse the existing solutiion, and inside `q9.txt`, list all the design and code smells the code contains.

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

**Make a note of any refactoring steps and/or Design Patterns discussed in the course that you use in `q9.txt`.**

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

**Make a note of any refactoring steps and/or Design Patterns discussed in the course that you use in `q9.txt`.**

The breakdown of marks for this question is as follows:
* Design (3 marks)
* Correctness (3 marks)
