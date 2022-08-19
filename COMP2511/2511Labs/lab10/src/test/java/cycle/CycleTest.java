package cycle;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Iterator;
import java.util.NoSuchElementException;

import org.junit.jupiter.api.Test;

import unsw.cycle.Cycle;

public class CycleTest {

    @Test
    public void simpleTest() {
        // this test should pass, as long as you don't change the methods given to you. This test is worth very little marks, as it works when given to you.
        // cycle 1
        Cycle<String> cycle1 = new Cycle<>(new ArrayList<>());

        assertEquals(0.0, cycle1.size());
        assertTrue(cycle1.isEmpty());

        cycle1.add("Apple");
        cycle1.add("Banana");
        cycle1.add("Pear");

        assertEquals(Double.POSITIVE_INFINITY, cycle1.size());
        assertFalse(cycle1.isEmpty());

        cycle1.add("Apricot");
        cycle1.add("Pineapple");

        assertEquals(Double.POSITIVE_INFINITY, cycle1.size());
        assertFalse(cycle1.isEmpty());

        // cycle 2
        Cycle<String> cycle2 = new Cycle<>(new ArrayList<>(Arrays.asList("Apple", "Banana", "Pear")));

        assertTrue(cycle2.contains("Apple"));
        assertFalse(cycle2.isEmpty());

        cycle2.remove("Apple");

        assertFalse(cycle2.contains("Apple"));
        assertFalse(cycle2.isEmpty());

        cycle2.add("Apple");
        cycle2.add("Apple");

        cycle2.remove("Apple");

        assertTrue(cycle2.contains("Apple"));
        assertFalse(cycle2.isEmpty());

        cycle2.remove("Apple");
        cycle2.remove("Banana");
        cycle2.remove("Pear");
        assertEquals(0.0, cycle2.size());
        assertTrue(cycle2.isEmpty());

        // cycle 3
        Cycle<String> cycle3 = new Cycle<>(new ArrayList<>());

        assertEquals(0.0, cycle3.size());
        assertTrue(cycle3.isEmpty());

        cycle3.add("Apple");

        assertEquals(Double.POSITIVE_INFINITY, cycle3.size());
        assertFalse(cycle3.isEmpty());

        cycle3.remove("Apple");
        assertEquals(0.0, cycle3.size());
        assertTrue(cycle3.isEmpty());

        assertEquals("Cycle items=[Apple, Banana, Pear, Apricot, Pineapple]", cycle1.toString());
    }

    @Test
    public void simpleEqualsTest() {
        Cycle<String> cycle1 = new Cycle<>(new ArrayList<>(Arrays.asList("Apple", "Banana", "Pear")));
        Cycle<String> cycle2 = new Cycle<>(new ArrayList<>(Arrays.asList("Apple", "Banana", "Pear")));
        assertEquals(cycle1, cycle2);

        cycle1.add("Mango");
        assertNotEquals(cycle1, cycle2);
    }

    public static void testEmptyCycleEquals() {
        Cycle<String> cycle1 = new Cycle<>(new ArrayList<>());
        Cycle<String> cycle2 = new Cycle<>(new ArrayList<>());
        assertEquals(cycle1, cycle2);
        assertEquals(cycle2, cycle2);

        cycle2.add("Apple");
        assertNotEquals(cycle1, cycle2);
        assertEquals(cycle2, cycle2);
    }

    @Test
    public void equalsTestShiftRight() {
        Cycle<String> cycle1 = new Cycle<>(new ArrayList<>(Arrays.asList("Apple", "Banana", "Pear")));
        Cycle<String> cycle2 = new Cycle<>(new ArrayList<>(Arrays.asList("Pear", "Apple", "Banana")));
        assertEquals(cycle1, cycle2);

        cycle2.add("Mango");
        assertNotEquals(cycle1, cycle2);
    }

    @Test
    public void equalsTestShiftLeft() {
        Cycle<String> cycle1 = new Cycle<>(new ArrayList<>(Arrays.asList("Apple", "Banana", "Pear")));
        Cycle<String> cycle2 = new Cycle<>(new ArrayList<>(Arrays.asList("Banana", "Pear", "Apple")));
        assertEquals(cycle1, cycle2);

        cycle2.add("Mango");
        assertNotEquals(cycle1, cycle2);

        Cycle<String> cycle3 = new Cycle<>(new ArrayList<>(Arrays.asList("Apple", "Banana", "Apricot")));
        Cycle<String> cycle4 = new Cycle<>(new ArrayList<>(Arrays.asList("Apple", "Apricot", "Banana")));
        assertNotEquals(cycle3, cycle4);

    }

    @Test
    public void equalsTestRepeatingCycle() {
        Cycle<String> cycle1 = new Cycle<>(new ArrayList<>(Arrays.asList("Apple", "Banana", "Apple", "Banana")));
        Cycle<String> cycle2 = new Cycle<>(new ArrayList<>(Arrays.asList("Apple", "Banana")));
        assertEquals(cycle1, cycle2);

        Cycle<String> cycle3 = new Cycle<>(new ArrayList<>(Arrays.asList("Apple", "Banana", "Apple", "Banana")));
        Cycle<String> cycle4 = new Cycle<>(new ArrayList<>(Arrays.asList("Banana")));
        assertNotEquals(cycle3, cycle4);
    }

    @Test
    public void testIteratorOneValue() {
        Cycle<String> cycle = new Cycle<>(new ArrayList<>(Arrays.asList("Apple")));
        Iterator<String> iterator = cycle.iterator();
        for (int i = 0; i < 100; i++) {
            assertEquals("Apple", iterator.next());
        }
    }

    @Test
    public void testIteratorTwoValues() {
        Cycle<String> cycle = new Cycle<>(new ArrayList<>(Arrays.asList("Apple", "Banana")));
        Iterator<String> iterator = cycle.iterator();
        for (int i = 0; i < 100; i++) {
            if (i % 2 == 0){
                assertEquals("Apple", iterator.next());
            } else {
                assertEquals("Banana", iterator.next());
            }
        }
    }

    @Test
    public void testIteratorEmptyCycle() {
        Cycle<String> cycle = new Cycle<>(new ArrayList<>());
        Iterator<String> iterator = cycle.iterator();
        assertThrows(NoSuchElementException.class, iterator::next);
    }
}
