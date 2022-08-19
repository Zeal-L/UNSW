package random;

import java.util.Random;

/**
 * A simple game, where a hero engages in battles.
 * The hero has an equally likely chance of succeeding as of failing.
 * @author Nick Patrikeos + @your name
 */
public class Game {

    private Random random;

    public Game(long seed) {
        random = new Random(seed);
    }

    public Game() {
        this(System.currentTimeMillis());
    }

    public boolean battle() {
        return random.nextBoolean();
    }

    public static void main(String[] args) {
        Game g = new Game();
        for (int i = 0; i < 100; i++) {
            if (g.battle()) {
                System.out.println("We won!! You are awesome!!");
            } else {
                System.out.println("Lost :(");
            }
        }
    }
}