package jql.v1;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertIterableEquals;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import unsw.jql.v1.Table;
import unsw.jql.v1.User;
import unsw.jql.v1.decorator.SelectDecorator;
import unsw.jql.v1.decorator.SkipDecorator;
import unsw.jql.v1.decorator.TakeDecorator;

/**
 * Tests for the object-oriented implementation of the JQL
 * 
 * @author Braedon Wooding & Nick Patrikeos
 */
public class JQLV1Test {
    public static List<User> sampleUsers() {
        List<User> users = new ArrayList<User>();
        users.add(new User(true, "A", "Devs"));
        users.add(new User(true, "B", "Devs"));
        users.add(new User(false, "C", "Testers"));
        users.add(new User(true, "D", "Business Analysts"));
        users.add(new User(true, "E", "CEO"));

        return users;
    }

    @Nested
    public class Task3IteratorInvalidationTests {
        @Test
        public void testSkip() {
            List<User> users = sampleUsers();
            Table<User> table = new Table<User>(users);
            assertIterableEquals(Arrays.asList(), new SkipDecorator<User>(table.toView(), 5));
            assertIterableEquals(users, new SkipDecorator<User>(table.toView(), 0));

            // it's okay to use streams in tests only
            assertIterableEquals(users.stream().skip(2).collect(Collectors.toList()),
                    new SkipDecorator<User>(table.toView(), 2));
        }
    }

    // Uncomment these tests once you are ready to test Task 4

    @Nested
    public class Task4TakeSelectTests {
        @Test
        public void testTake() {
            List<User> users = sampleUsers();
            Table<User> table = new Table<User>(users);

            assertIterableEquals(Arrays.asList(), new TakeDecorator<User>(table.toView(), 0));
            assertIterableEquals(users, new TakeDecorator<User>(table.toView(), 5));
            // there is no take(int) in java so we'll just make do with a more 'awful'
            // styled variant here
            assertIterableEquals(users.stream().takeWhile(x -> !x.userId().equals("C")).collect(Collectors.toList()),
                    new TakeDecorator<User>(table.toView(), 2));
            assertIterableEquals(
                    users.stream().skip(2).takeWhile(x -> x.userId().equals("D") == false).collect(Collectors.toList()),
                    new TakeDecorator<User>(new SkipDecorator<User>(table.toView(), 2), 1));

        }

        @Test
        public void testCountWithSkipAndTake() {
            List<User> users = new ArrayList<User>();
            users.add(new User(true, "A", "Devs"));
            users.add(new User(true, "B", "Devs"));
            users.add(new User(false, "C", "Testers"));
            users.add(new User(true, "D", "Business Analysts"));
            users.add(new User(true, "E", "CEO"));

            Table<User> table = new Table<User>(users);
            assertEquals(5, table.toView().count());
            assertEquals(0, new TakeDecorator<User>(table.toView(), 0).count());
            assertEquals(0, new SkipDecorator<User>(table.toView(), 5).count());
            assertEquals(1, new TakeDecorator<User>(new SkipDecorator<User>(table.toView(), 4), 1).count());
        }

        @Test
        public void testSelect() {
            List<User> users = new ArrayList<User>();
            users.add(new User(true, "A", "Devs"));
            users.add(new User(true, "B", "Devs"));
            users.add(new User(false, "C", "Testers"));
            users.add(new User(true, "D", "Business Analysts"));
            users.add(new User(true, "E", "CEO"));

            Table<User> table = new Table<User>(users);
            assertIterableEquals(Arrays.asList("Devs", "Devs", "Testers", "Business Analysts", "CEO"),
                    new SelectDecorator<User, String>(table.toView(), x -> x.jobTitle()));
            assertIterableEquals(Arrays.asList("Devs"),
                    new TakeDecorator<String>(new SelectDecorator<User, String>(table.toView(), x -> x.jobTitle()), 1));
        }
    }
}
