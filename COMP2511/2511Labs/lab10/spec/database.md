## Lab 10 - Revision Exercise - Database

In 2022 COMP2511 is asked to build a new mark database to be able to store/update/query student marks.  To begin with you've been asked to implement a simple proof of concept of the architecture within the span of a meeting (around 1-1.5 hours).

This question is broken up into several parts which progress in difficulty.

**There are cases where a Design Pattern discussed in the course may be suitable to use and you are encouraged to use at least 1-2** across the question.  Make a brief note where you have used a Design Pattern by putting a comment denoting which one and how it was implemented in `q10.txt`.

There are some simple tests in `database/SimpleTest.java`, the following is a simple example of creating a database, ingesting some data, and performing a query

```java
// The following creates a database with 6 columns
Database db = new Database(Arrays.asList(
        new Column("StudentId", ColumnType.TEXT),
        new Column("Tutorial", ColumnType.TEXT),
        new Column("GroupSuffix", ColumnType.TEXT),
        new Column("Assignment", ColumnType.MARK),
        new Column("Lab1", ColumnType.MARK),
        new Column("Lab2", ColumnType.MARK)));

// The following inserts 4 records based upon the header
db.ingest(
    // header
    "StudentId|Tutorial|GroupSuffix|Assignment|Lab1|Lab2\n" +
    "z1234    |tue15a  |elderberry |35        |1   |2\n" +
    "z2345    |tue15a  |pineapple  |25        |2   |1\n" +
    "z3456    |wed18a  |elderberry |39        |0   |2\n" +
    "z4567    |tue15a  |pineapple  |17        |2   |2"
    // make sure you don't end the last line with a `\n`
);

// This performs a query to look for all records where the student 
Query query = db.parseQuery("Tutorial = 'tue15a' AND Lab1 > 1");
List<Map<String, Object>> results = db.queryComplex(query);
```

#### a) Creating a Database (5 marks)

Your first task is to implement the constructor.

```java
Database(List<Column> columns);
```

Column has the following definition

```java
public class Column {
    public enum ColumnType {
        MARK,
        TEXT;
    }

    private String name;
    private ColumnType type;

    // with appopriate getters
}
```

> You can presume that once the database is created, the database structure from that point will remain the same.

To get marks for this section you'll need to implement the following method inside of your implementation of Database

```java
public class Database {
    // Should return the columnType for the given columnName, if the column doesn't exist it should return null.
    public ColumnType getColumn(String name);

    // there are other methods but just return null/nothing, make sure the code still compiles!
}
```

> Hint: You want to make sure you choose your internal data structure for this correct early on, think about what sort of data structure let's you map a column name to a type (you don't/shouldn't just keep them as lists)!  Have a look at querySimple (at the end of part b) and the typical structure you'll want your results to be.

#### b) Inserting New Records (7 marks)

To begin with we'll look at a simpler case for the database.  In this case the records don't currently exist in the database.  Records are ingested through the use of the `ingest` method as per below;

```java
public class Database {
    // should return number of new records inserted
    public int ingest(String contents);

    // there are other methods but just return null/nothing, make sure the code still compiles!
}
```

Contents is structured in a similar fashion to a CSV (comma separated values) but instead uses vertical bars `|` i.e. as follows;

```csv
StudentId | Tutorial | GroupSuffix | Assignment | Lab1 | Lab2
z1234     | tue15a   | melons      | 35         | 1    | 2
```

The first row lists all the column names, and all other rows list data.  Any columns that aren't specified are presumed to have the value `""` for text and `0` for marks.  Note the columns are NOT ordered accordingly to the original list of columns provided and could be in any order (though there won't be duplicates in a given row).  

> Unlike CSV all whitespace should be trimmed from the values and column names.

To get marks for this question (there are partial marks if you can just do ingest) we also need to be able to read data from the database this is done through the `querySimple` method as follows;

```java
public class Database {
    // Queries database for all records where columnName has a value that .equals() value.
    public List<Map<String, Object>> querySimple(String columnName, Object value);

    // there are other methods but just return null/nothing, make sure the code still compiles!
}
```

This query just does an equals comparison on the specified column comparing it to `value`, you can presume no values are ever null (since as specified before, empty columns are either `""` for text, or `0` for marks).

The type returned should be a list of records, where each 'record' is a mapping of column names to the column value.  The types of the 'value' should just be `String` or `Integer` (you can use `int`).  The ordering here doesn't matter.

#### c) Updating Column Data (5 marks)

Next we need to be able to update data in the database

```java
public class Database {
    public void updateData(String queryColumnName, Object queryValue, String columnName, Object columnValue);

    // there are other methods but just return null/nothing, make sure the code still compiles!
}
```

This behaves very similar to `querySimple()` (part b) and should update all records where the `queryColumnName = queryValue` to have the `columnName = columnValue`.

So for example the following shows a simple update;

```java
// This updates everyone who has Tutorial = tue15a to have an assignment mark of 40.
db.updateData("Tutorial", "tue15a", "Assignment", 40);
```

#### d) Derived Columns (10 marks)

Next we need to add derived columns to the database, these use formulae based on other columns in the database to calculate their value.

They are added through the following command;

```java
public class Database {
    public void addDerivedColumn(String columnName, List<String> dependencies, Function<Map<String, Object>, Object> compute);

    // there are other methods but just return null/nothing, make sure the code still compiles!
}
```

For example, we could add a derived column that has the following signature;

```java
db.addDerviedColumn("TotalMark", Arrays.asList("Assignment", "Lab1", "Lab2"), (cols) -> (int)cols.get("Lab1") + (int)cols.get("Lab2") + (int)cols.get("Assignment"));
```

The dictionary that is given to the `compute` method only consists of the columns that exist in `dependencies` and the derived field should only be re-evaluated if any of the dependencies are changed.

For example, only the `Lab1`, `Lab2`, and `Assignment` exist in the `cols` dictionary in the above example since they are the only dependencies.  For example, you won't be given dependencies such that `A` depends on `B` and `B` depends on `A`.

Derived columns return either `String` or `Integer` (`int`).

#### e) Queries (13 marks)

Queries are an important part of databases and so we have a more complicated query method that is structured as so.

```java
public class Database {
    // Query is an empty class that you can do whatever you want to (add subclasses/methods/whatever)
    // the only requirement is that the name remains the same.
    public Query parseQuery(String query);

    // Queries database using already compiled Query
    // If a record matches twice you can add it twice (i.e. you don't have to handle distinct)
    public List<Map<String, Object>> queryComplex(Query query);

    // there are other methods but just return null/nothing, make sure the code still compiles!
}
```

The query is structured with the following format;

```
StudentId = 'z1234' AND Assignment = 10 OR Tutorial = 'tue13a' AND Assignment > 15
```

- There are 2 operators that are supported `=` and `>`
- There are 2 boolean operators (AND/OR), where AND has higher precedence than OR so the above query is actually (using brackets to denote precedence); `(StudentId = 'z1234' AND Assignment = 10) OR (Tutorial = 'tue13a' AND Assignment > 15)`
- `'text'` denotes a block of text otherwise it's a mark/integer i.e. `'z1234'`

The parsing code has been implemented for you inside of `Database::parseQuery` (and the methods it calls) with some todos for you to add code to create your query representation.
