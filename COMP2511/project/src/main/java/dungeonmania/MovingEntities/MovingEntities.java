package dungeonmania.MovingEntities;

import dungeonmania.Entity;
import dungeonmania.util.Position;

public abstract class MovingEntities extends Entity {

    private double currentHealth;
    private double currentAttack;
    public MovingEntities(String type, boolean isBlocked, boolean isInteractable, Position position, double attack, double health) {
        super(type, isBlocked, isInteractable, position);
        currentHealth = health;
        currentAttack = attack;
    }
    public double getCurrAttack(){
        return currentAttack;
    }

    public void setCurrAttack(double currAttack){
        this.currentAttack = currAttack;
    }

    public double getCurrHealth(){
        return currentHealth;
    }

    public void setCurrHealth(double currHealth){
        this.currentHealth = currHealth;
    }
    public abstract void move();
}
