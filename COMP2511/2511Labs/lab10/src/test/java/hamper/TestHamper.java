package hamper;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

import unsw.hamper.Apple;
import unsw.hamper.ArrayListItemHamper;
import unsw.hamper.Avocado;
import unsw.hamper.Count;
import unsw.hamper.Fruit;
import unsw.hamper.FruitHamper;
import unsw.hamper.Hamper;

public class TestHamper {

    @Test
    public void simpleTest() {
        Hamper<Fruit> fruitHamper = new ArrayListItemHamper<Fruit>();
        fruitHamper.add(new Apple("Gala", 450, 100));
        fruitHamper.add(new Apple("Fuji", 400, 100));
        fruitHamper.add(new Avocado("Hass", 300));

        assertEquals(1, fruitHamper.count(new Apple("Gala", 450, 100)));
        assertEquals(1, fruitHamper.count(new Apple("Fuji", 400, 100)));
        assertEquals(1, fruitHamper.count(new Avocado("Hass", 300)));


        // The same element again
        fruitHamper.add(new Apple("Gala", 450, 100));
        assertEquals(2, fruitHamper.count(new Apple("Gala", 450, 100)));
        assertEquals(1, fruitHamper.count(new Apple("Fuji", 400, 100)));
        assertEquals(1, fruitHamper.count(new Avocado("Hass", 300)));
    }

    @Test
    public void removeTest() {
        Hamper<Fruit> fruitHamper = new ArrayListItemHamper<Fruit>();
        fruitHamper.add(new Apple("Gala", 450, 100));
        fruitHamper.add(new Apple("Fuji", 400, 100), 2);
        fruitHamper.add(new Avocado("Hass", 300), 3);

        fruitHamper.remove(new Avocado("Hass", 300), 2);
        assertEquals(1, fruitHamper.count(new Apple("Gala", 450, 100)));
        assertEquals(2, fruitHamper.count(new Apple("Fuji", 400, 100)));
        assertEquals(1, fruitHamper.count(new Avocado("Hass", 300)));

        fruitHamper.remove(new Apple("Fuji", 400, 100), 2);
        assertEquals(1, fruitHamper.count(new Apple("Gala", 450, 100)));
        assertEquals(0, fruitHamper.count(new Apple("Fuji", 400, 100)));
        assertEquals(1, fruitHamper.count(new Avocado("Hass", 300)));

        fruitHamper.remove(new Apple("Gala", 450, 100), 3);
        assertEquals(0, fruitHamper.count(new Apple("Gala", 450, 100)));
        assertEquals(0, fruitHamper.count(new Apple("Fuji", 400, 100)));
        assertEquals(1, fruitHamper.count(new Avocado("Hass", 300)));

        // Check the invariant hasn't been broken
        for (Count<Fruit> c : fruitHamper)
            assertTrue(c.getCount() > 0);
    }

    @Test
    public void sizeTest() {
        Hamper<Fruit> fruitHamper = new ArrayListItemHamper<Fruit>();
        fruitHamper.add(new Apple("Gala", 450, 100));
        fruitHamper.add(new Apple("Fuji", 400, 100), 2);
        fruitHamper.add(new Avocado("Hass", 300), 3);

        assertEquals(6, fruitHamper.size());
    }

    @Test
    public void sumTest() {
        Hamper<Apple> h = new ArrayListItemHamper<Apple>();
        Apple a1 = new Apple("Gala", 450, 100);
        Apple a2 = new Apple("Fuji", 400, 100);
        Apple a3 = new Apple("Granny Smith", 500, 150);
        h.add(a1, 2);
        h.add(a2, 3);
        h.add(a3);

        Hamper<Apple> h2 = new ArrayListItemHamper<Apple>();
        h2.add(a2);
        h2.add(a1);

        Hamper<Apple> h3 = h.sum(h2);

        assertEquals(3, h3.count(a1));
        assertEquals(4, h3.count(a2));
        assertEquals(1, h3.count(a3));

        int counter = 0;
        for (Count<Apple> c : h3) {
            if (c.getElement().equals(a1))
                assertEquals(3, c.getCount());
            else if (c.getElement().equals(a2))
                assertEquals(4, c.getCount());
            else if (c.getElement().equals(a3))
                assertEquals(1, c.getCount());
            counter++;
        }

        assertEquals(3, counter);
    }

    @Test
    public void simpleEqualityTest() {
        Hamper<Apple> h = new ArrayListItemHamper<Apple>();
        Apple a1 = new Apple("Gala", 450, 100);
        Apple a2 = new Apple("Fuji", 400, 100);
        Apple a3 = new Apple("Granny Smith", 500, 150);
        h.add(a1, 2);
        h.add(a2, 3);
        h.add(a3);

        assertTrue(h.equals(h));

        Hamper<Apple> h2 = new ArrayListItemHamper<Apple>();
        h2.add(a3);
        h2.add(a1, 2);
        h2.add(a2, 3);

        assertTrue(h.equals(h2));
        assertTrue(h2.equals(h));

        h2.add(a1);

        assertFalse(h.equals(h2));
        assertFalse(h2.equals(h));

        Hamper<Apple> h3 = new ArrayListItemHamper<Apple>();
        h3.add(a3);
        h3.add(a1, 2);
        h3.add(a2, 3);
        h3.add(new Apple("Honey Crisp", 350, 80));

        assertFalse(h.equals(h3));
        assertFalse(h3.equals(h));
    }

    @Test
    public void fruitHamperTest(){
        FruitHamper fh1 = new FruitHamper();
        FruitHamper fh2 = new FruitHamper();
        Apple a1 = new Apple("Gala", 450, 100);
        Apple a2 = new Apple("Fuji", 400, 100);
        Apple a3 = new Apple("Granny Smith", 500, 150);
        Apple a4 = new Apple("Honey Crisp", 350, 80);
        Apple a5 = new Apple("Ambrosia", 600, 200);
        Avocado av1 = new Avocado("Hass", 300);
        Avocado av2 = new Avocado("Maluma", 400);

        fh1.add(a1);
        fh1.add(a2);
        fh1.add(a3);
        fh1.add(a4);
        fh1.add(av1);
        
        fh2.add(a1);
        fh2.add(a2);
        fh2.add(a3);
        fh2.add(a4);
        fh2.add(av1);

        fh1.add(a5);
        assertEquals(fh1, fh2);  // since need 2 avocados, fh1 shouldnt have changed

        fh1.add(av2);
        assertNotEquals(fh1, fh2);

        fh2.add(av2);
        assertEquals(fh1, fh2);
    }

    @Test
    public void fruitHamperPriceTest(){
        FruitHamper fh1 = new FruitHamper();
        Apple a1 = new Apple("Gala", 450, 100);
        Apple a2 = new Apple("Fuji", 400, 100);
        Apple a3 = new Apple("Granny Smith", 500, 150);
        Apple a4 = new Apple("Honey Crisp", 350, 80);
        Avocado av1 = new Avocado("Hass", 300);
        Avocado av2 = new Avocado("Maluma", 400);
        fh1.add(a1);
        fh1.add(a2);
        fh1.add(a3);
        fh1.add(a4);
        fh1.add(av1);
        fh1.add(av2);
        // 235875 == ceiling((450*100+400*100+500*150+350*80+300+400)*1.25)
        assertEquals(fh1.getPrice(), 235875);
    }

}
