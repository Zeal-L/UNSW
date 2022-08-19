package database;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.stream.Collectors;

import org.junit.jupiter.api.Test;

import unsw.database.Column;
import unsw.database.Database;
import unsw.database.Query;
import unsw.database.Column.ColumnType;

public class DatabaseTest {

    // getColumn and constructor
    @Test
    public static void SimpleTestPartA() {
        System.err.println("== Starting Test A ==");

        Database db = new Database(Arrays.asList(
                new Column("StudentId", ColumnType.TEXT),
                new Column("Tutorial", ColumnType.TEXT),
                new Column("GroupSuffix", ColumnType.TEXT),
                new Column("Assignment", ColumnType.MARK),
                new Column("Lab1", ColumnType.MARK),
                new Column("Lab2", ColumnType.MARK)));

        checkColumn(db, "StudentId", ColumnType.TEXT);
        checkColumn(db, "Tutorial", ColumnType.TEXT);
        checkColumn(db, "GroupSuffix", ColumnType.TEXT);
        checkColumn(db, "Assignment", ColumnType.MARK);
        checkColumn(db, "Lab1", ColumnType.MARK);
        checkColumn(db, "Lab2", ColumnType.MARK);

        // doesn't exist
        checkColumn(db, "Lab3", null);

        System.err.println("== Test A Successful ==");
    }

    // Ingest data
    @Test
    public static void SimpleTestPartB() {
        System.err.println("== Starting Test B ==");

        Database db = new Database(Arrays.asList(
                new Column("StudentId", ColumnType.TEXT),
                new Column("Tutorial", ColumnType.TEXT),
                new Column("GroupSuffix", ColumnType.TEXT),
                new Column("Assignment", ColumnType.MARK),
                new Column("Lab1", ColumnType.MARK),
                new Column("Lab2", ColumnType.MARK)));

        // We recommend writing your tests like this rather than using raw files.
        db.ingest(
            // header
            "StudentId|Tutorial|GroupSuffix|Assignment|Lab1|Lab2\n" +
            // first row
            "z1234    |tue15a  |elderberry |35        |1   |2\n" +
            // second row
            "z2345    |tue15a  |pineapple  |25        |2   |1"
            // make sure you don't end the last line with a `\n`
        );

        Map<String, Map<String, Object>> expectedObjects = new HashMap<>();

        Map<String, Object> z1234 = new HashMap<>();
        z1234.put("StudentId", "z1234");
        z1234.put("Tutorial", "tue15a");
        z1234.put("GroupSuffix", "elderberry");
        z1234.put("Assignment", 35);
        z1234.put("Lab1", 1);
        z1234.put("Lab2", 2);

        Map<String, Object> z2345 = new HashMap<>();
        z2345.put("StudentId", "z2345");
        z2345.put("Tutorial", "tue15a");
        z2345.put("GroupSuffix", "pineapple");
        z2345.put("Assignment", 25);
        z2345.put("Lab1", 2);
        z2345.put("Lab2", 1);

        expectedObjects.put("z1234", z1234);
        checkQueryResults("StudentId", expectedObjects, db.querySimple("StudentId", "z1234"));

        expectedObjects.clear();
        expectedObjects.put("z2345", z2345);
        checkQueryResults("StudentId", expectedObjects, db.querySimple("StudentId", "z2345"));

        expectedObjects.clear();
        expectedObjects.put("z2345", z2345);
        expectedObjects.put("z1234", z1234);
        checkQueryResults("StudentId", expectedObjects, db.querySimple("Tutorial", "tue15a"));

        System.err.println("== Test B Successful ==");
    }

    // Updating Data
    @Test
    public static void SimpleTestPartC() {
        System.err.println("== Starting Test C ==");

        Database db = new Database(Arrays.asList(
                new Column("StudentId", ColumnType.TEXT),
                new Column("Tutorial", ColumnType.TEXT),
                new Column("GroupSuffix", ColumnType.TEXT),
                new Column("Assignment", ColumnType.MARK),
                new Column("Lab1", ColumnType.MARK),
                new Column("Lab2", ColumnType.MARK)));

        // We recommend writing your tests like this rather than using raw files.
        db.ingest(
            // header
            "StudentId|Tutorial|GroupSuffix|Assignment|Lab1|Lab2\n" +
            // first row
            "z1234    |tue15a  |elderberry |35        |    |2\n" +
            // first row
            "z2345    |tue15a  |pineapple  |40        |2   |2"
            // make sure you don't end the last line with a `\n`
        );

        Map<String, Map<String, Object>> expectedObjects = new HashMap<>();

        Map<String, Object> z1234 = new HashMap<>();
        z1234.put("StudentId", "z1234");
        z1234.put("Tutorial", "tue15a");
        z1234.put("GroupSuffix", "elderberry");
        z1234.put("Assignment", 35);
        z1234.put("Lab1", 0);
        z1234.put("Lab2", 2);

        Map<String, Object> z2345 = new HashMap<>();
        z2345.put("StudentId", "z2345");
        z2345.put("Tutorial", "tue15a");
        z2345.put("GroupSuffix", "pineapple");
        z2345.put("Assignment", 40);
        z2345.put("Lab1", 2);
        z2345.put("Lab2", 2);

        expectedObjects.put("z1234", z1234);
        expectedObjects.put("z2345", z2345);

        checkQueryResults("StudentId", expectedObjects, db.querySimple("Tutorial", "tue15a"));

        // update lab1 for student z1234
        db.updateData("StudentId", "z1234", "Lab1", 2);
        z1234.put("Lab1", 2);
        checkQueryResults("StudentId", expectedObjects, db.querySimple("Tutorial", "tue15a"));

        // update assignment for both students in tutorial tue15a
        db.updateData("Tutorial", "tue15a", "Assignment", 20);
        z1234.put("Assignment", 20);
        z2345.put("Assignment", 20);
        checkQueryResults("StudentId", expectedObjects, db.querySimple("Tutorial", "tue15a"));

        System.err.println("== Test C Successful ==");
    }

    // Derived Columns
    @Test
    public static void SimpleTestPartD() {
        System.err.println("== Starting Test D ==");

        Database db = new Database(Arrays.asList(
            new Column("StudentId", ColumnType.TEXT),
            new Column("Tutorial", ColumnType.TEXT),
            new Column("GroupSuffix", ColumnType.TEXT),
            new Column("Assignment", ColumnType.MARK),
            new Column("Lab1", ColumnType.MARK),
            new Column("Lab2", ColumnType.MARK)));

        db.addDerivedColumn("TotalMark", Arrays.asList("Assignment", "Lab1", "Lab2"), (cols) -> (int)cols.get("Lab1") + (int)cols.get("Lab2") + (int)cols.get("Assignment"));

        // We recommend writing your tests like this rather than using raw files.
        db.ingest(
            // header
            "StudentId|Tutorial|GroupSuffix|Assignment|Lab1|Lab2\n" +
            "z1234    |tue15a  |elderberry |35        |1   |2\n" +
            "z2345    |tue15a  |pineapple  |25        |2   |1"
            // make sure you don't end the last line with a `\n`
        );

        db.addDerivedColumn("ProjectGroup", Arrays.asList("Tutorial", "GroupSuffix"), (cols) -> cols.get("Tutorial") + "_" + cols.get("GroupSuffix"));

        Map<String, Map<String, Object>> expectedObjects = new HashMap<>();

        Map<String, Object> z1234 = new HashMap<>();
        z1234.put("StudentId", "z1234");
        z1234.put("Tutorial", "tue15a");
        z1234.put("GroupSuffix", "elderberry");
        z1234.put("Assignment", 35);
        z1234.put("Lab1", 1);
        z1234.put("Lab2", 2);
        z1234.put("ProjectGroup", "tue15a_elderberry");
        z1234.put("TotalMark", 38);

        Map<String, Object> z2345 = new HashMap<>();
        z2345.put("StudentId", "z2345");
        z2345.put("Tutorial", "tue15a");
        z2345.put("GroupSuffix", "pineapple");
        z2345.put("Assignment", 25);
        z2345.put("Lab1", 2);
        z2345.put("Lab2", 1);
        z2345.put("ProjectGroup", "tue15a_pineapple");
        z2345.put("TotalMark", 28);

        expectedObjects.put("z1234", z1234);
        checkQueryResults("StudentId", expectedObjects, db.querySimple("StudentId", "z1234"));

        expectedObjects.clear();
        expectedObjects.put("z2345", z2345);
        checkQueryResults("StudentId", expectedObjects, db.querySimple("StudentId", "z2345"));

        expectedObjects.clear();
        expectedObjects.put("z2345", z2345);
        expectedObjects.put("z1234", z1234);
        checkQueryResults("StudentId", expectedObjects, db.querySimple("Tutorial", "tue15a"));

        db.updateData("StudentId", "z1234", "ProjectGroup", "tue15a_pineapple");
        db.updateData("StudentId", "z2345", "Lab1", 0);
        db.updateData("StudentId", "z2345", "Lab2", 2);

        z1234.put("ProjectGroup", "tue15a_pineapple");
        z2345.put("Lab1", 0);
        z2345.put("Lab2", 2);
        z2345.put("TotalMark", 27);

        expectedObjects.clear();
        expectedObjects.put("z2345", z2345);
        expectedObjects.put("z1234", z1234);
        checkQueryResults("StudentId", expectedObjects, db.querySimple("Tutorial", "tue15a"));

        System.err.println("== Test D Successful ==");
    }

    // Complex Queries
    @Test
    public static void SimpleTestPartE() {
        System.err.println("== Starting Test E ==");

        Database db = new Database(Arrays.asList(
                new Column("StudentId", ColumnType.TEXT),
                new Column("Tutorial", ColumnType.TEXT),
                new Column("GroupSuffix", ColumnType.TEXT),
                new Column("Assignment", ColumnType.MARK),
                new Column("Lab1", ColumnType.MARK),
                new Column("Lab2", ColumnType.MARK)));

        // I recommend writing your tests like this rather than using raw files.
        db.ingest(
            // header
            "StudentId|Tutorial|GroupSuffix|Assignment|Lab1|Lab2\n" +
            "z1234    |tue15a  |elderberry |35        |1   |2\n" +
            "z2345    |tue15a  |pineapple  |25        |2   |1\n" +
            "z3456    |wed18a  |elderberry |39        |0   |2\n" +
            "z4567    |tue15a  |pineapple  |17        |2   |2"
            // make sure you don't end the last line with a `\n`
        );

        Map<String, Map<String, Object>> expectedObjects = new HashMap<>();

        Map<String, Object> z1234 = new HashMap<>();
        z1234.put("StudentId", "z1234");
        z1234.put("Tutorial", "tue15a");
        z1234.put("GroupSuffix", "elderberry");
        z1234.put("Assignment", 35);
        z1234.put("Lab1", 1);
        z1234.put("Lab2", 2);

        Map<String, Object> z2345 = new HashMap<>();
        z2345.put("StudentId", "z2345");
        z2345.put("Tutorial", "tue15a");
        z2345.put("GroupSuffix", "pineapple");
        z2345.put("Assignment", 25);
        z2345.put("Lab1", 2);
        z2345.put("Lab2", 1);

        Map<String, Object> z3456 = new HashMap<>();
        z3456.put("StudentId", "z3456");
        z3456.put("Tutorial", "wed18a");
        z3456.put("GroupSuffix", "elderberry");
        z3456.put("Assignment", 39);
        z3456.put("Lab1", 0);
        z3456.put("Lab2", 2);

        Map<String, Object> z4567 = new HashMap<>();
        z4567.put("StudentId", "z4567");
        z4567.put("Tutorial", "tue15a");
        z4567.put("GroupSuffix", "pineapple");
        z4567.put("Assignment", 17);
        z4567.put("Lab1", 2);
        z4567.put("Lab2", 2);

        // basically just a simple query
        expectedObjects.put("z1234", z1234);
        Query query = db.parseQuery("StudentId = 'z1234'");
        checkQueryResults("StudentId", expectedObjects, db.queryComplex(query));

        // checking >
        expectedObjects.clear();
        expectedObjects.put("z1234", z1234);
        expectedObjects.put("z2345", z2345);
        expectedObjects.put("z4567", z4567);
        query = db.parseQuery("Lab1 > 0");
        checkQueryResults("StudentId", expectedObjects, db.queryComplex(query));

        // checking AND
        expectedObjects.clear();
        expectedObjects.put("z1234", z1234);
        expectedObjects.put("z2345", z2345);
        query = db.parseQuery("Tutorial = 'tue15a' AND GroupSuffix = 'elderberry'");
        checkQueryResults("StudentId", expectedObjects, db.queryComplex(query));

        // checking OR
        expectedObjects.clear();
        expectedObjects.put("z2345", z2345);
        expectedObjects.put("z3456", z3456);
        query = db.parseQuery("Lab1 = 0 OR Lab2 = 1");
        checkQueryResults("StudentId", expectedObjects, db.queryComplex(query));

        // checking combination of and/or
        expectedObjects.clear();
        expectedObjects.put("z1234", z1234);
        expectedObjects.put("z2345", z2345);
        expectedObjects.put("z3456", z3456);
        expectedObjects.put("z4567", z4567);
        query = db.parseQuery("Tutorial = 'tue15a' OR GroupSuffix = 'elderberry' AND Lab1 = 0");
        checkQueryResults("StudentId", expectedObjects, db.queryComplex(query));

        // checking other combination of or/and
        expectedObjects.clear();
        expectedObjects.put("z1234", z1234);
        expectedObjects.put("z2345", z2345);
        expectedObjects.put("z4567", z4567);
        // second part of OR condition won't match z3456
        query = db.parseQuery("Tutorial = 'tue15a' OR GroupSuffix = 'elderberry' AND Lab1 > 0");
        checkQueryResults("StudentId", expectedObjects, db.queryComplex(query));

        System.err.println("== Test E Successful ==");
    }

    /* == Helpers == */

    // this is a pretty long function so I wouldn't waste time reading through how it works,
    // the errors/exceptions are detailed enough that they should help by itself.
    public static void checkQueryResults(String idField, Map<String, Map<String, Object>> expected, List<Map<String, Object>> actual) {
        Set<Object> seenEntities = new HashSet<>();

        for (Map<String,Object> row : actual) {
            if (row.containsKey(idField)) {
                if (expected.containsKey(row.get(idField))) {
                    seenEntities.add(row.get(idField));
                    Map<String, Object> expectedRow = expected.get(row.get(idField));
                    if (!row.keySet().equals(expectedRow.keySet())) {
                        throw new RuntimeException("There were extra unexpected columns... we expected the following columns (comma separated); [" +
                        expectedRow.keySet().stream().collect(Collectors.joining(",")) +
                            "] but we got [" + row.keySet().stream().collect(Collectors.joining(",")) + "]"
                        );
                    }

                    for (Map.Entry<String,Object> column : row.entrySet()) {
                        // confirm values
                        if (!Objects.equals(expectedRow.get(column.getKey()), column.getValue())) {
                            throw new RuntimeException("Column " + column.getKey() + " did not match for record " + idField + " = " + row.get(idField) +
                            " we were expecting the value " + column.getKey() + " = " + expectedRow.get(column.getKey()) + 
                            " but we got " + column.getKey() + " = " + column.getValue());
                        }
                    }
                } else {
                    throw new RuntimeException("Unexpected row, we weren't expecting a row where " + idField + " = " + row.get(idField));
                }
            } else {
                throw new RuntimeException("We were expecting all rows to have a column called " + idField + " but it seems that the row containing these values did not; " +
                    row.entrySet().stream().map(x -> x.getKey() + " = " + x.getValue()).collect(Collectors.joining(", "))
                );
            }
        }
        
        // confirm we didn't miss anything
        if (seenEntities.size() != expected.size()) {
            throw new RuntimeException(
                "We were expecting " + expected.size() + " rows but we got " + seenEntities.size() + " instead... " +
                "the rows that were missing had the following values for the column " + idField + " [" +
                expected.entrySet().stream()
                    .filter(x -> !seenEntities.contains(x.getKey()))
                    .map(x -> x.getKey())
                    .collect(Collectors.joining(", ")) +
                "]"
            );
        }
    }

    public static void checkColumn(Database db, String columnName, ColumnType expectedType) {
        ColumnType actualType = db.getColumn(columnName);
        if (!Objects.equals(actualType, expectedType)) {
            throw new RuntimeException("Test Failed... we expected " + expectedType.toString() + " but got "
                    + (actualType != null ? actualType.toString() : "null"));
        }
    }
}
