package Behavioral.StrategyPattern;

import Behavioral.StrategyPattern.Strategy.Strategy;

public class Animal {
    private String type;
    private String name;
    private Strategy strategy;
    

    public Animal(String type, String name, Strategy strategy) {
        this.type = type;
        this.name = name;
        this.strategy = strategy;
    }
    public void whoami() {
        System.out.print("I am a " + type + " and my name is " + name + ", and ");
        this.strategy.movement();
    }

    public void setStrategy(Strategy strategy) {
        this.strategy = strategy;
    }
}

