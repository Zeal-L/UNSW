## Lab 07 - Core Exercise - Boolean Logic 

> ℹ️ You will need to make a **Private** (set to Course Staff can view only) Blog Post on WebCMS for this activity. Put your answers to the questions inside it.

### Background

[Boolean logic](https://en.wikipedia.org/wiki/Boolean_algebra) is mathematical formalism for descibing logic, named after [George Bool](https://en.wikipedia.org/wiki/George_Boole). Computer scientists love boolean logic because it's all about manipulating binary state. In fact, you're using boolean logic whenever you combine two expressions using `&&` or `||` and when you negate an expresion using `!`. Since you've made it this far through COMP2511, we hope you know how boolean `AND`, `OR` and `NOT` work, but just in case you need a refresher, you can see the [truth tables](https://en.wikipedia.org/wiki/Truth_table) for these operators on Wikipedia.

A Boolean expression is a combination of variables, joined with Boolean operators. We will use parentheses to make the order of operations clear and unambiguous. The following are all valid Boolean expressions for example:

* `x` AND `y`
* `x`
* (`x` OR `y`) AND NOT (`z` OR (`a` AND `x`))

When all of the variables in these expressions are assigned a value (either `true` or `false`), then the whole expression evaluates to either `true` or `false`. 

For example, the following diagram represents a boolean expression which is an AND expression, and contains two sub-expressions, both of which are leaf boolean nodes. 

<img src='imgs/img1.png'>

Evaluating this expression would return `false`, and pretty-printing this expression would print:

```
(AND true false)
```

The values of the leaf nodes are defined in the construction of the expression.

Here is another example:

<img src='imgs/img2.png'>

```java
// Pretty print: (OR false (NOT false))
// Evaluates to true
```

<img src='imgs/img3.png'>

```java
// Pretty print (OR true (NOT (AND false (OR true false))))
// Evaluates to true
```


### Task 1) Composite Pattern 🧠

Use the Composite Pattern to implement an evaluator for Boolean expressions using a tree of Boolean expression objects. 

**Q1: What are the compound nodes and the leaf nodes in this problem? Write the answer in your blog post.**

There is a type `BooleanNode` which you can use to represent the composite type. 

**Q2: Will you use keep the `BooleanNode` as an `abstract class` or use an `interface` to represent the composite type?**

**Task**: Inside `BooleanEvaluator.java` there are two static methods which take in a `BooleanNode` and evaluate, and provide a pretty-printed representation of the node respectively. 

```java
public static boolean evaluate(BooleanNode expression);
```

```java
public static String prettyPrint(BooleanNode expression);
```

### Task 2) Factory Pattern 🏭

Creating composite objects is all very well, but they don't just appear out of nothing ready for us to use. 

**Q3: In our factory, what are the different types of objects we need to create? What are the different fields they will have?**

**Task**: Use the Factory Pattern to implement `NodeFactory`, which should contain a static method that allows the user to pass in a `JSONObject`, and returns a corresponding `BooleanNode` object with the parsed expression tree. For example:

```javascript
{ 
    "node": 
    "and", 
    "subnode1" : {
        "node": 
        "or", 
        "subnode1": {
            "node": "value", "value": true
        },
        "subnode2": {
            "node": "value", "value": false
        }
    },
    "subnode2": {
        "node": "value", "value": true
    }
}
```

parses to the expression:

```
(AND (OR true false) true)
```

when pretty printed.