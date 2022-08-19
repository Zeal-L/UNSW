## Lab 02 - Core Exercise - Staff  🔱

Modify the class StaffMember (inside package `staff`) so that it satisfies the following requirements:

* Attributes to store the staff member’s name, salary, hire date, and end date.
* Appropriate constructors, getters, setters, and other methods you think are necessary.
* Overridden `toString()` and `equals(..)` methods. 
* Javadoc for all non-overriding methods and constructors.

Create a sub-class of `StaffMember` called `Lecturer` in the same package with the following requirements:

* An attribute to store the school (e.g. CSE) that the lecturer belongs to
* An attribute that stores the academic status of the lecturer (e.g A for an Associate Lecturer, B  for a Lecturer, and C for a Senior Lecturer)
* Appropriate getters and setters.
* An overriding `toString()` method that includes the school name and academic level.
* An overriding `equals(...)` method.
* Javadoc for all non-overriding methods and constructors.

Create a class `StaffTest` in the package `staff.test` to test the above classes. It should contain:

* A method `printStaffDetails(...)` that takes a `StaffMember` as a parameter and invokes the `toString()` method on it to print the details of the staff.
* A `main(...)` method that:

  * Creates a `StaffMember` with a name and salary of your choosing.
  * Creates an instance of `Lecturer` with a name, salary, school and academic status of your choosing.
  * Calls `printStaffDetails(...)` twice with each of the above as arguments.
  * Tests the `equals(..)` method of the two classes. 

You do not need to write any JUnit tests for this exercise (though you can if you would like).
