package jql.v2;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertIterableEquals;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.ExecutionException;
import java.util.stream.Collectors;

import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import unsw.jql.v2.Fruit;
import unsw.jql.v2.Table;
import unsw.jql.v2.TableView;
import unsw.jql.v2.User;

/**
 * Tests for the functional implementation of the JQL
 * 
 * @author Braedon Wooding & Nick Patrikeos
 */
public class JQLV2Test {
    
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
    public class Task2GenericsTests {
        @Test
        public void testRegression() {
            List<User> users = sampleUsers();
            Table table = new Table(users);
            assertIterableEquals(users, table.toView());
        }

        // Uncomment the test below once you are ready to test Task 2

        
        @Test
        public void testTableIsGeneric() {
            List<Fruit> users = Arrays.asList(new Fruit[]{new Fruit("apple", "red", 3), new Fruit("orange", "orange", 2), new Fruit("apple", "green", 6)});
            Table<Fruit> table = new Table<Fruit>(users);
            assertIterableEquals(users, table.toView());
        }
        
    }

    // Uncomment all these tests once you have are ready to test Task 2
    // If you have completed Task 2 they should compile but will still fail

    
    @Nested
    public class Task5SelectSkipFunctionalTests {
        @Test
        public void testTake() {
            List<User> users = sampleUsers();

            Table<User> table = new Table<User>(users);
            assertIterableEquals(Arrays.asList(), table.toView().take(0));
            assertIterableEquals(users, table.toView().take(5));

            // there is no take(int) in java so we'll just make do with a more 'awful' styled variant here
            assertIterableEquals(users.stream().takeWhile(x -> x.userId().equals("C") == false).collect(Collectors.toList()), table.toView().take(2));
        }

        @Test
        public void testSkip() {
            List<User> users = sampleUsers();
            Table<User> table = new Table<User>(users);

            assertIterableEquals(Arrays.asList(), table.toView().skip(5));
            assertIterableEquals(users, table.toView().skip(0));
            // it's okay to use streams in tests only
            assertIterableEquals(users.stream().skip(2).collect(Collectors.toList()), table.toView().skip(2));

            assertIterableEquals(users.stream().skip(2).takeWhile(x -> x.userId().equals("D") == false).collect(Collectors.toList()), table.toView().skip(2).take(1));
        }

        @Test
        public void testCount() {
            List<User> users = sampleUsers();
            Table<User> table = new Table<User>(users);

            assertEquals(5, table.toView().count());
            assertEquals(0, table.toView().take(0).count());
            assertEquals(0, table.toView().skip(5).count());
            assertEquals(1, table.toView().skip(4).take(1).count());
        }

        @Test
        public void testSelect() {
            List<User> users = sampleUsers();
            Table<User> table = new Table<User>(users);

            assertIterableEquals(Arrays.asList("Devs", "Devs", "Testers", "Business Analysts", "CEO"), table.toView().select(x -> x.jobTitle()));
            assertIterableEquals(Arrays.asList("Devs"), table.toView().select(x -> x.jobTitle()).take(1));
        }
    }
    
    // @Nested
    // public class Task6WhereTests {
    //     @Test
    //     public void testWhere() {
    //         List<User> users = sampleUsers();
    //         Table<User> table = new Table<User>(users);
            
    //         TableView<String> y = table.toView().where(x -> x.isActive()).select(x -> x.jobTitle());
    //         assertIterableEquals(Arrays.asList("Devs", "Devs", "Business Analysts", "CEO"), y);
    //         TableView<String> z = table.toView().where(x -> x.jobTitle().contains("t")).select(x -> x.jobTitle());
    //         assertIterableEquals(Arrays.asList("Testers", "Business Analysts"), z);
    //     }
    // }
    
    @Nested
    public class Task7ParallelReduceTests {
        @Test
        public void testReduceRegression() {
            List<User> users = new ArrayList<User>();
            users.add(new User(true, "A", "Devs"));
            users.add(new User(true, "B", "Devs"));
            users.add(new User(false, "C", "Testers"));
            users.add(new User(true, "D", "Business Analysts"));
            users.add(new User(true, "E", "CEO"));

            Table<User> table = new Table<User>(users);
            
            assertEquals(false, table.toView().select(x -> x.isActive()).reduce(Boolean::logicalAnd, true));
            assertEquals(true, table.toView().select(x -> x.isActive()).reduce(Boolean::logicalOr, true));
            assertEquals("Devs, Devs, Testers, Business Analysts, CEO", table.toView().select(x -> x.jobTitle()).reduce((acc, cur) -> acc.isEmpty() ? cur : acc + ", " + cur, ""));
        }

        @Test 
        public void testParallelReduce() throws InterruptedException, ExecutionException {
            // This is our flaky test :'(
            // Run it a few times before you start Task 7 to see it fail 
            
            List<User> users = new ArrayList<User>();
            users.add(new User(true, "A", "Devs"));
            users.add(new User(true, "B", "Devs"));
            users.add(new User(false, "C", "Testers"));
            users.add(new User(true, "D", "Business Analysts"));
            users.add(new User(true, "E", "CEO"));

            Table<User> table = new Table<User>(users);
            
            assertEquals(false, table.toView().select(x -> x.isActive()).reduce(Boolean::logicalAnd, true));
            assertEquals(true, table.toView().select(x -> x.isActive()).reduce(Boolean::logicalOr, true));
            assertEquals(false, table.toView().select(x -> x.isActive()).parallelReduce(Boolean::logicalAnd, Boolean::logicalAnd, true, 16));
            assertEquals(true, table.toView().select(x -> x.isActive()).parallelReduce(Boolean::logicalOr, Boolean::logicalOr, true, 16));
        }

        @Test
        public void stressTestParallelReduce() throws InterruptedException, ExecutionException {
            List<User> users = new ArrayList<User>();
            for (int i = 0; i < 100; i++) {
                users.add(new User(true, "A" + i, "A" + i));
            }
            Table<User> table = new Table<User>(users);

            assertEquals(true, table.toView().select(x -> x.isActive()).parallelReduce((curr, init) -> {
                try {
                    Thread.sleep(1000); // sleep for 1 second to simulate an 'expensive' operation
                } catch (InterruptedException e) {}

                return init && curr;
            }, Boolean::logicalAnd, true, 16));
        }
    }
    
}
