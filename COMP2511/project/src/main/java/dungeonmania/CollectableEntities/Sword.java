package dungeonmania.CollectableEntities;

import dungeonmania.Buff;
import dungeonmania.Weapon;
import dungeonmania.util.Position;

public class Sword extends CollectableEntities implements Weapon {
    private static int durability;
    private static int attack;
    private int currentDurability;
    private int currentAttack;
    public Sword(int x, int y, String type) {
        super(type, false, new Position(x, y));
        currentDurability = durability;
        currentAttack = attack;
    }
    public static void setDurability(int durability) {
        Sword.durability = durability;
    }
    public static void setAttack(int attack) {
        Sword.attack = attack;
    }

    @Override
    public int getCurrDurability() {
        return currentDurability;
    }

    @Override
    public void setCurrDurability(int durability) {
        this.currentDurability = durability;
    }

    @Override
    public Buff getBuff() {
        return new Buff(currentAttack,0,0,getId(),getType());
    }
}
