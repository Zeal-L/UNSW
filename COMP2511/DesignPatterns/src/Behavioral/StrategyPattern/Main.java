package Behavioral.StrategyPattern;

import Behavioral.StrategyPattern.Strategy.Fly;

public class Main {
    public static void main(String[] args) throws Exception {
        Animal dog = new Dog("doggy");
        Animal bird = new Bird("birddy");
        dog.whoami();
        bird.whoami();

        dog.setStrategy(new Fly());
        dog.whoami();
    }
}
