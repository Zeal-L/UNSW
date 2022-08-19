## Lab 10 - Revision Exercise - Business Rules

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

All transformations/groups/operator's behaviour is explained in detail below; Feel free to use these enums in your solution.

```java
public enum BusinessRuleOperators {
    /**
     * Given A, and B are either integers or doubles
     * evalutes to true if A > B else false.
     * 
     * Should throw BusinessRuleException("Both arguments have to be numeric")
     * if either A or B isn't an integer or a double or if B isn't supplied.
     */
    GREATER_THAN,

    /**
     * Is a unary operator returns false if the argument given is either
     * null or a string consisting purely of spaces (or is empty) otherwise it returns true.
     * 
     * Hint: `string.isBlank()` will tell you if a string is empty/consists purely of spaces.
     * 
     * If the type is an integer/boolean/double it should always return true.
     * 
     * Ignores second argument if supplied.
     */
    IS_NOT_BLANK;
}

public enum BusinessRuleGroupTypes {
    /**
     * Evaluates the two business rules supplied and if both are true evaluates to true
     * else it evaluates to false.
     */
    AND,

    /**
     * Evaluates the two business rules supplied and if either are true evaluates to true
     * else it evaluates to false.
     */
    OR;
}
```

Your task is to design a solution that allows a user to create arbitrary rules as shown above. You must design your solution using one or more of the design patterns discussed in the course such that it could be easily extended (for additional operators)

You'll be filling in the stub provided in `BusinessRuleMain.java` which given a json string representing the input json rule it'll return a class implementing the business rule interface, which then given a dictionary representing the variables will resolve to a boolean.

You can use either gson or org.json (both libraries we've provided throughout the term) to implement your solution. You must obey the following; - JSON data should be extracted into classes and you should not store any json objects

You must also provide brief justification for your design choices in Q1.txt. Please note that it doesn't have to be very long, just a paragraph should suffice. You will be awarded marks for proper justifications.