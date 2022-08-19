## Lab 04 - Challenge Exercise - Rational Numbers 🧮

In many situations (both in OOP and procedural programming) you have probably encountered, you have been given some sort of library / ADT / API / class which has a series of methods/routes/functions and allows you to call these methods, and the problem has been to use the methods to make some sort of game, or to make something useful happen.

In this exercise, we're going to reverse the roles. Your friend Attila has written a program inside `FunFractions.java` which plays a game for kids learning about fractions. 

We don't want to use Java `double` floating point numbers for this since they have a limited number of decimal places and [can't accurately represent or manipulate](https://en.wikipedia.org/wiki/Floating-point_arithmetic#Accuracy_problems) all rational numbers (fractions). You must create your own `Rational` class to store and manipulate rational numbers.

Attila's job is to implement the game which uses the `Rational` class that you will write. Unfortunately, Attila didn't consult with you to come up with an interface, or contract between the class and the class user and just assumed what the methods would be. His solution doesn't currently compile and is commented out.

Your task is to firstly write the declaration for the `Rational` class inside `Rational.java` which specifies the contract, including all preconditions, postconditions and invariants for each of the methods that are not constructors or `toString`. Then, implement the methods so that the game in `FunFractions.java` works.

### Construction and `toStr`

Your class should support creating any valid rational number with a numerator and denominator.

The number ²/₃ is created as `Rational frac = new Rational(2, 3)`.

You do not need to handle zero denominators or any cases of division by zero.

When `toString` is called, your `Rational` class should display in simplified form. For example, `Rational(21, 12)` should be displayed as 1³/₄. The small nubmers must be done using unicode superscript and subscript digits. These have been provided to you in `SUPER_NUMS` and `SUB_NUMS` in `Rational.java`.

### Methods

* The `.equals()` methods should return `true` if the numbers are equivalent. For example `Rational(4, 8)` is equivalent to `Rational(1, 2)`
* The `add`, `subtract`, `multiply` and `divide` methods should all work as expected on two `Rational` objects and return a new `Rational` instance without modifying the originals.

### The Game

When you have implemented all the methods correctly, the game should work like this:

```
What is 4 × 1¹/₄?
0) 5
1) 1⁴/₅
2) ¹/₂
3) 1¹/₅
> 0
Correct!

What is 1 ÷ ²/₅?
0) 1¹/₅
1) ¹/₄
2) 2¹/₂
3) 1
> 1
Incorrect. The correct answer was: 2¹/₂

What is ⁷/₉ - 1¹/₂?
0) 10
1) -¹³/₁₈
2) 3
3) ⁷/₁₀
> 1
Correct!

What is ³/₈ × 1²/₇?
0) 2
1) ²⁷/₅₆
2) 0
3) 1¹/₂
> 
Invalid input. The correct answer was: ²⁷/₅₆
```
