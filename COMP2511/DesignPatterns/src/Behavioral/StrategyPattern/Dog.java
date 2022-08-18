package Behavioral.StrategyPattern;

import Behavioral.StrategyPattern.Strategy.Walk;

public class Dog extends Animal {
    public Dog(String name) {
        super("dog", name, new Walk());
    }
}

