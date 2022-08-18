package Behavioral.StrategyPattern;

import Behavioral.StrategyPattern.Strategy.Fly;

public class Bird extends Animal {
    public Bird(String name) {
        super("bird", name, new Fly());
    }
}

