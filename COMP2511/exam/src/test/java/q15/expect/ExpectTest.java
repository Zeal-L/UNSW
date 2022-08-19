package q15.expect;

import static org.junit.jupiter.api.Assertions.assertThrows;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Iterator;
import java.util.List;
import java.util.function.Consumer;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;

import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

public class ExpectTest {
    
    @Nested
    public class PartABasicOperationsTests {
        @Test
        public void testToEqual() {
            Expect<String> e = new Expect<String>("hello");
            assertDoesNotThrow(() -> e.toEqual("hello").evaluate());
            assertThrows(ExpectationFailedException.class, () -> e.toEqual("world").evaluate());
        }

        @Test
        public void testLessThan() {
            Expect<Integer> e = new Expect<Integer>(1);
            assertDoesNotThrow(() -> e.lessThan(4).evaluate());
            assertThrows(ExpectationFailedException.class, () -> e.lessThan(0).evaluate());
        }

        @Test
        public void testGreaterThanOrEqualTo() {
            Expect<Integer> e = new Expect<Integer>(1);
            assertDoesNotThrow(() -> e.greaterThanOrEqualTo(0).evaluate());
            assertDoesNotThrow(() -> e.greaterThanOrEqualTo(1).evaluate());
            assertThrows(ExpectationFailedException.class, () -> e.greaterThanOrEqualTo(2).evaluate());
        }
    }

    @Nested
    public class PartBDecorationOperationsTests {
        @Test
        public void testNotEqual() {
            Expect<String> e = new Expect<String>("hello");
            assertDoesNotThrow(() -> e.toEqual("world").not().evaluate());
            assertThrows(ExpectationFailedException.class, () -> e.toEqual("hello").not().evaluate());
        }
    }

    @Nested
    public class PartCRunnableTests {
        @Test
        public void testExpectRunnableThrows() {
            ExpectRunnable<Runnable> exec = new ExpectRunnable<Runnable>(() -> {
                throw new RuntimeException("hello");
            });
    
            assertDoesNotThrow(() -> exec.toThrow(RuntimeException.class).evaluate());
        }
    
        @Test
        public void testExpectRunnableDoesNotThrow() {
            ExpectRunnable<Runnable> exec = new ExpectRunnable<Runnable>(() -> System.out.println("hello"));
            
            assertThrows(ExpectationFailedException.class, () -> exec.toThrow(RuntimeException.class).evaluate());
        }
    }

    @Nested
    public class PartDParameterisedTests {
        @Test
        public void testParameterisedSimple() {
            ExpectParameterised<Integer, Consumer<Integer>, List<Integer>> exp = 
                    new ExpectParameterised<Integer, Consumer<Integer>, List<Integer>>(
                    i -> {
                        Expect<Integer> e = new Expect<Integer>(i);
                        Expect<Integer> e2 = e.lessThan(10); // Create expression i < 10
                        e2.evaluate();
                    },
                    new ArrayList<Integer>(Arrays.asList(8, 9, 10, 11)) // List of parameters
            );

            Iterator<Runnable> iter = exp.iterator();
            assertDoesNotThrow(() -> iter.next().run()); // 8 < 10, true
            assertDoesNotThrow(() -> iter.next().run()); // 9 < 10, true
            assertThrows(ExpectationFailedException.class, () -> iter.next().run()); // 10 < 10, false - fails
            assertThrows(ExpectationFailedException.class, () -> iter.next().run()); // 11 < 10, false - fails

            assertThrows(ExpectationFailedException.class, () -> exp.evaluateAll()); // Not all true, fails
        }
    }


}