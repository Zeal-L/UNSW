## Lab 10 - Revision Exercise - Theory Questions

The following is a compilation of theory questions from past exams. 

A lot of the questions relate to Java Programming and syntax which isn't going to be in the exam directly (you'll have to write Java code of course but we won't ask you questions about syntax). They're also of a different style to the questions you'll be asked in the exam.

### Question 1

What is the output of the code below?

<img src="imgs/Quiz01_Q1.gif">

<ol type="a">
    <li>Fred</li>
    <li>Bob</li>
    <li>null</li>
    <li>empty string</li>
</ol>

### Question 2

Suppose the following two classes are defined:

```java
public abstract class Figure {...}
public class Rectangle extends Figure {...}
public abstract class 3DFigure extends Figure {...}
```

Which of the following instantiations is not valid?

<ol type="a">
    <li><code>Rectangle r = new Rectangle(…..);</code></li>
    <li><code>Figure f = new Rectangle(….);</code></li>
    <li><code>Figure f = new 3DFigure(…);</code></li>
</ol>

### Question 3

Using the class diagram below, examine the code that follows and choose which of the following statements below does not compile?

<img src="imgs/Quiz01_Q3.gif">

```java
Employee e = new Director();
Analyst a = new Analyst();
Manager m = new Director();
```

<ol type="a">
    <li><code>e.addEmployee()</code></li>
    <li><code>m.addEmployee(a);</code></li>
    <li><code>((Director)m).approveExpense(10000)</code></li>
</ol>

### Question 4

The code below produces a compilation error. Examine the code and choose the fix that will enable the classes to compile.

```java
public class Account {
    private double balance;
    public Account (double balance) { this.balance = balance; }
    // other getter and setter for balance
}
public class Savings extends Account {
    private double interestRate;
    public Savings(double rate) {
        this.interestRate = rate;
    }
}
```

<ol type="a">
    <li>Call the setBalance method of the Account from Savings</li>
    <li>Change the access of interestRate to public</li>
    <li>Add a no-arg constructor to class Savings</li>
    <li>Replace the constructor in Savings with one that calls the constructor of Account using super.</li>
</ol>

### Question 5

Which of the following statements are true about immutable classes (select all that apply)?

<ol type="a">
    <li>They do not need to be copied or cloned.</li>
    <li>They have a constructor that enables an object to be instantiated the first time with values</li>
    <li>An object instance cannot be changed after it is created</li>
    <li>They can provide setter methods to update their fields from outside the class</li>
</ol>

### Question 6

An abstract method must not have:

<ol type="a">
    <li>a method implementation</li>
    <li>a return value</li>
    <li>method parameters</li>
    <li>a protected access modifier</li>
</ol>

### Question 7

Which of the following is untrue about interfaces and inheritance?

<ol type="a">
    <li>A class can extend multiple interfaces</li>
    <li>An interface can extend multiple interfaces</li>
    <li>A class can extend another class and implement multiple interfaces</li>
    <li>All methods in an interface are implicitly abstract, unless provided with a default implementation</li>
</ol>

### Question 8

Which of the following statements is untrue about method overriding?

<ol type="a">
    <li>Constructors cannot be overridden </li>
    <li>If a static method in the base class, is redefined in the sub-class, the later hides the method in the base class </li>
    <li>In method overriding, run-time polymorphism ensures that instantiated, the call to any method in the base class will be resolved to the correct method, based on the run-time type of the object instantiated.</li>
    <li>During method overriding, the overridden method in the sub-class can specify a weaker access modifier </li>
</ol>

### Question 9

Choose the incorrect statement

a. The principle of least knowledge reduces dependencies between objects and promotes loose coupling

b. The code below is a good example of the principle of least knowledge

```java
Driver driver = car.getDriver()
Address driverAddress = driver.getAddress()
```

c. According to the principle of least knowledge, accessing the methods on objects returned by a method call is invalid

d. The principle of least knowledge states that accessing methods of objects passed in as parameters or instantiated inside the method is valid

### Question 10

Which of the following statements is FALSE in relation to generics?

<ol type="a">
    <li>A generic class used without type arguments is known as a raw type</li>
    <li>You cannot instantiate an array of a generic type using new operator e.g., <code>T[] anArray = new T[100]</code></li>
    <li>Consider the following method, <code>someMethod(Box<Number> n) { /*…. */}</code>, this method can take in a Box<Integer> or Box<Double></li>
</ol>

### Question 11

Consider the following code:

```java
public interface xyz {
void abc() throws IOException;
}
public interface pqr {
void abc() throws FileNotFoundException;
}
public class Implementation implements xyz, pqr {
// insert code
{ /*implementation*/ }
}
```

### Question 12

Which of the following statement(s) can you insert in place of “// insert code” comment?

<ol type="a">
    <li><code>public void abc() throws FileNotFoundException, IOException</code></li>
    <li><code>public void abc() throws IOException</code></li>
    <li><code>public void abc() throws FileNotFoundException</code></li>
</ol>

### Question 13

A design pattern used to enhance a component’s functionality dynamically at run-time is:

<ol type="a">
    <li>Composite Pattern</li>
    <li>Decorator Pattern</li>
    <li>Abstract Factory Pattern</li>
    <li>Observer Pattern</li>
</ol>

### Question 14

Identify the pattern used in this code:

```java
LineNumberReader lnr = new LineNumberReader(
                       new BufferedReader(
                       new FileReader(“./test.c")));
String str = null;
while((str = lnr.readLine()) != null)
System.out.println(lnr.getLineNumber() + ": " + str);
```

<ol type="a">
    <li>Strategy</li>
    <li>State</li>
    <li>Factory</li>
    <li>Decorator</li>
</ol>

### Question 15

Which of the following exceptions must be handled by a try-catch block or declared?

<ol type="a">
    <li><code>NullPointerException</code></li>
    <li><code>MalformedURLException</code></li>
    <li><code>ClassCastException</code></li>
    <li><code>ArithmeticException</code></li>
</ol>

### Question 16

Which of the following statements is NOT true?

<ol type="a">
    <li>The Builder Pattern is a violation of the law of demeter</li>
    <li>Decorators provide a flexible alternative to inheritance for extending functionality.</li>
    <li>The observer pattern provides a design where subjects and observers are loosely coupled</li>
    <li>The Factory Method Design Pattern uses inheritance to solve the problem of creating objects without specifying their exact object classes</li>
</ol>

### Question 17

Which one of the following is not a code smell?

<ol type="a">
    <li>Classes that not only passively store data, but also methods to operate on the data</li>
    <li>Large conditional logic blocks</li>
    <li>Methods making extensive use of another class</li>
</ol>

### Question 18

A class that isn’t doing enough work to justify its maintenance is an example of code smell

<ol type="a">
    <li>Data Class</li>
    <li>Inappropriate intimacy</li>
    <li>Data Clumps</li>
    <li>Lazy class</li>
</ol>

### Question 11

When code has sets of variables usually passed together in multiple places, this is an example of the code smell

<ol type="a">
    <li>Duplicated code</li>
    <li>Inappropriate intimacy</li>
    <li>Data Clumps</li>
    <li>Lazy class</li>
</ol>

### Question 12

Which of the following statements about design pattern is NOT true?

<ol type="a">
    <li>The collections.sort() method is a good example of the strategy Pattern</li>
    <li>The Java IO makes use of the composite pattern</li>
    <li>The Java collection framework makes use of the Iterator Pattern</li>
</ol>

### Question 13

An online camping store, sells different kinds of camping equipment. Items selected by the customer are added to a shopping cart. When a user clicks on the checkout Button, the application is required to calculate the total amount to be paid. The calculation logic for each item type varies, and we want to move all the calculation logic to one separate class, to decouple the different items from the calculation logic applied on them. As the application iterates through the disparate set of items of the shopping cart, we apply the price computation logic in the class to each item type. Which of the following patterns would be useful to design this scenario?

<ol type="a">
    <li>Strategy Pattern</li>
    <li>Decorator Pattern</li>
    <li>Iterator Pattern</li>
    <li>Visitor Patter</li>
</ol>

### Question 14

Which of the following statements is/are true?
Select one or more:

<ol type="a">
    <li>The adapter class maps/joins functionality of two different types/interfaces and offers additional functionality.</li>
    <li>The decorator design pattern does not satisfy Open-Closed Principle.</li>
    <li>Tree structures are normally used to implement Composite Patterns.</li>
    <li>Graph structures are normally used to represent Builder Patterns.</li>
</ol>

### Question 15

For the Template Pattern, which of the following statements is/are true?

Select one or more:

<ol type="a">
    <li>Template Method lets subclasses redefine an algorithm, keeping certain steps invariants.</li>
    <li>Subclasses of the Template Method can redefine only certain parts of a behaviour without changing the algorithm's structure.</li>
    <li>A subclass calls the operations of a parent class and not the other way around.</li>
    <li>Template pattern works on the object level, letting you switch behaviours at runtime</li>
</ol>

### Question 16

Which of the following statements is/are true?
Select one or more:

<ol type="a">
    <li>In Java, errors (like OutOfMemoryError, VirtualMachineError, etc.) are Checked Exceptions.</li>
    <li>The Java IO makes use of the strategy pattern.</li>
    <li>Pre-conditions in an inherited overridden method must be stronger.</li>
    <li>All other choices are incorrect.</li>
</ol>

### Question 17

The Factory Method design pattern solves problems like:
Select one or more:

<ol type="a">
    <li>How can an object be created so that subclasses can redefine which class to instantiate?</li>
    <li>How can a class defer instantiation to its superclass?</li>
    <li>How can the way an object is created be changed at run-time?</li>
    <li>How can object creation that is distributed across multiple classes be centralized?</li>
</ol>

### Question 18

In the composite pattern, not placing child-related operations in the component interface does what?
Select one:

<ol type="a">
    <li>Prioritises type safety over uniformity</li>
    <li>Prioritises uniformity over type safety</li>
    <li>Prioritises polymorphism over uniformity</li>
    <li>Prioritises efficiency over type safety</li>
</ol>

### Question 19

Which of the following statements is/are correct?
Select one or more:

<ol type="a">
    <li>Encapsulate what does not vary is a key design principle.</li>
    <li>Polymorphism requires multiple inheritance.</li>
    <li>Favour inheritance over composition is a key design principle.</li>
    <li>A subclass can offer more behaviour than its super class.</li>
</ol>

### Question 20

Suppose the following classes/interfaces are defined:

```java
public interface Car {...}
public class SportsCar implements Car {...}
public interface FamilyCar extends Car {...}
public abstract class CityCar implements FamilyCar {...}
```

Which of the following instantiations/statements are valid?
Select one or more:

<ol type="a">
    <li><code>FamilyCar c = new Car(...);</code></li>
    <li><code>FamilyCar c = new SportsCar(...);</code></li>
    <li><code>FamilyCar c = new CityCar(...);</code></li>
</ol>

### Question 21

For generic types in Java, which of the following is/are incorrect?
Select one or more:

<ol type="a">
    <li>List<Integer> is a subtype of List<Object>.</li>
    <li>List<?> matches List<Object> and List<Integer>.</li>
    <li>The wildcard < ? extends Foo > matches Foo and any subtype of Foo, where Foo is any type.</li>
    <li>The wildcard < ? extends Foo > matches Foo and any super type of Foo, where Foo is any type.</li>
    <li>None of the other three choices are correct.</li>
</ol>

### Question 22

Consider a vending machine application that dispenses products when the proper combination of coins is deposited. Which of the following design patterns is suitable for such a vending machine application?

<ol type="a">
    <li>Strategy Pattern</li>
    <li>Composite Pattern</li>
    <li>Visitor Pattern</li>
    <li>State Pattern</li>
</ol>

### Question 23

You are implementing a health application that monitors heart rate of a patient. If the heart rate of a patient is out of the required range, the application needs to inform all the relevant doctors and nurses. Doctors and nurses responsible for a patient may change over time.

### Question 24

A user bought an application that reads data in JSON format, and displays results on a web page. Later, the user realised that one of their data sources is in XML format. Unfortunately, the user does not have access to the source code of the application, so it is not possible to change the application.

### Question 25

Briefly explain the important differences between the Decorator Pattern and the Builder Pattern, as discussed in the lectures.

### Question 26

Briefly explain the important differences between the Factory Method and Abstract Factory Method Patterns, as discussed in the lectures.