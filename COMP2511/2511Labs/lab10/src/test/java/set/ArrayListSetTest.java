package set;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Iterator;

import static org.junit.jupiter.api.Assertions.assertEquals;


import org.junit.jupiter.api.Test;

import unsw.set.fruit.Apple;
import unsw.set.fruit.Fruit;
import unsw.set.fruit.Orange;

/**
 * Tests for ArrayListSet.
 * 
 * @author Nick Patrikeos
 */
class ArrayListSetTest {

    /*@Test
    public void testSimpleIntegration() {
        Set<String> set = new ArrayListSet<String>();
        set.add("Hello");
        set.add("Hello");
        set.add("World");
        assertTrue(set.contains("Hello"));
        assertTrue(set.contains("World"));
        assertEquals(2, set.size());

        set.remove("Hello");
        assertFalse(set.contains("Hello"));
        assertTrue(set.contains("World"));
        assertEquals(1, set.size());
    }

    @Test
    public void testIterator() {
        Set<String> set = new ArrayListSet<String>();
        set.add("Hello");
        set.add("Hello");
        set.add("World");

        Iterator<String> iter = set.iterator();
        
        for (int i = 0; i < 2; i++) {
            iter.next();
        }
    }

    @Test
    public void testSubsetOf() {
        Set<Fruit> fruit = new ArrayListSet<Fruit>();
        fruit.add(new Apple("Gala"));
        fruit.add(new Apple("Fuji"));
        fruit.add(new Orange("Navel"));

        Set<Apple> apples = new ArrayListSet<Apple>();
        apples.add(new Apple("Gala"));
        apples.add(new Apple("Fuji"));

        assertTrue(apples.subsetOf(fruit));
        assertFalse(fruit.subsetOf(apples));

        fruit.remove(new Apple("Fuji"));

        assertFalse(apples.subsetOf(fruit));
    }

    @Test
    public void testEqualitySameType() {
        Set<Fruit> fruit1 = new ArrayListSet<Fruit>();
        fruit1.add(new Apple("Fuji"));
        fruit1.add(new Apple("Gala"));
        fruit1.add(new Orange("Navel"));
        
        Set<Fruit> fruit2 = new ArrayListSet<Fruit>();
        fruit2.add(new Apple("Gala"));
        fruit2.add(new Apple("Fuji"));
        fruit2.add(new Orange("Navel"));

        assertTrue(fruit1.equals(fruit2));
        assertTrue(fruit2.equals(fruit1));
    }

    @Test
    public void testUnionIntersection() {
        Set<Fruit> fruit1 = new ArrayListSet<Fruit>();
        fruit1.add(new Apple("Pink Lady"));
        fruit1.add(new Apple("Granny Smith"));

        Set<Fruit> fruit2 = new ArrayListSet<Fruit>();
        fruit2.add(new Orange("Blood Orange"));
        fruit2.add(new Apple("Granny Smith"));

        Set<Fruit> intersectSet = fruit1.intersection(fruit2);
        assertTrue(intersectSet.contains(new Apple("Granny Smith")));
        assertEquals(1, intersectSet.size());
        assertEquals(fruit1.intersection(fruit2), fruit2.intersection(fruit1));

        Set<Fruit> unionSet = fruit1.union(fruit2);
        assertTrue(unionSet.contains(new Apple("Pink Lady")));
        assertTrue(unionSet.contains(new Apple("Granny Smith")));
        assertTrue(unionSet.contains(new Orange("Blood Orange")));
        assertEquals(3, unionSet.size());
        assertEquals(fruit1.union(fruit2), fruit2.union(fruit1));
    }*/
}
