## Lab 10 - Revision Exercise - Set 

### Task 1) `ArrayList` Set 📃

Inside `src/unsw/collections`, there is a `Set` interface which represents a generic [mathematical set](https://en.wikipedia.org/wiki/Set_(mathematics)). There's already an existing `Set` object in `java.util`, but in this exercise we are going to implement our own set that uses Generic Programming. 

Create a new file called `ArrayListSet.java` which implements the `Set` interface, and models a Set that is implemented using an `ArrayList` (i.e. the class is simply a wrapper around a Java `ArrayList`, the underlying data structure, and provides a few abstractions that allow it to be conceptually treated as a Set). Your task is to implement the methods without making any changes to the `Set` interface and ensuring it is consistent with the documentation and contract, including the invariant specified in the interface docstring. 

Your `ArrayListSet` also needs to override the `equals` method. 

Some basic tests have been provided which don't currently compile as the classes themselves do not exist. Feel free to add more tests if you wish.

<details>
<summary>Hint</summary>

* The constructor for `ArrayListSet` should take in no arguments.
* Use your knowledge of Set definitions from Discrete Maths to help you implement the class, or research online.
* For `equals(...)`, you will need to use `instanceof` and wildcards (`?`) in the body of the method.

</details>

### Task 2) `Array` Set 📜

In this exercise, we will be writing another implementation of the `Set` interface - this time, using a primitive array to store our set of generic elements. We'd never actually do this in a Java program such as your project as you would always use an `ArrayList` or some other Java-provided collection object. This exercise aims to make you think like someone who would write the `ArrayList` library - because under the hood, an `ArrayList` is just a primitive array with some fancy abstractions that make it nice for us to use. 

Create a new file called `ArraySet.java` which implements `Set`, using a primitive array to store elements. Your `ArraySet` also needs to override the `equals` method. 

Most of the implementation will be relatively straightforward; you'll just need to keep track of more things in a C-style of programming in utilising the array. There are a few curvy parts, however:

* Java, for all its glorious purpose [doesn't allow us to instantiate arrays of generic objects, among other restrictions](https://docs.oracle.com/javase/tutorial/java/generics/restrictions.html). We can get around this using a small hack in the `ArraySet` constructor:

    ```java
    public ArraySet(Class<E> cls, int length) {
        elements = (E[]) Array.newInstance(cls, length);
        // ...
    }
    ```

    The `Class` class is the class that models classes themselves (that was a mouthful). In simpler terms, if you want to talk about the definition of a class type itself in Java, as an object that you can see and touch like a `String`, `Random`, `SpaceXSatellite` or `LoopManiaWorld`, `Class` is the type of these objects. 

* Constructing an `ArraySet` is a bit ugly because of this. We pass in `String.class` which is our `Class` object, and the length of the array. Ideally, we wouldn't have to pass in any arguments (like with `ArrayListSet`) and instead do something like `new ArraySet<String, 3>` which is much cleaner, but as you have probably figured out by now, Java can be quite clunky at times. Here is how we can instantiate our object.

    ```java
    Set<String> set = new ArraySet<String>(String.class, 3);
    ```

* What about the `.iterator` method? We will need to write this ourselves. Use the Iterator Pattern by defining a class `ArraySetIterator` which is parameterised with a generic type. The `.iterator` method in `ArraySet` should return a new instance of `ArraySetIterator`.

Some basic tests have been provided. They don't compile as the classes themselves do not exist. Feel free to add more tests if you wish.

