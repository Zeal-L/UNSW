package random;

import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.ArrayList;
import java.util.List;

import org.junit.jupiter.api.Test;

public class GameTest {
    @Test
    public void testHalfTheProbability() {
        Game g = new Game();
        int counter = 0;
        for (int i = 0; i < 1000; i++) {
            if (g.battle()) {
                counter++;
            }
        }
        System.out.println(counter);
        assertTrue(550 > counter);
        assertTrue(450 < counter);
    }

    @Test
    public void testSameRandom() {
        int fixedSeed = 12345;
        Game tempA = new Game(fixedSeed);
        List<Boolean> listA = new ArrayList<>();
        for (int i = 0; i < 1000000; i++) {
            listA.add(tempA.battle());
        }
        Game tempB = new Game(fixedSeed);
        List<Boolean> listB = new ArrayList<>();
        for (int i = 0; i < 1000000; i++) {
            listB.add(tempB.battle());
        }
        assertTrue(listA.equals(listB));
    }
}