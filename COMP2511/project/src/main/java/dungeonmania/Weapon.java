package dungeonmania;

public interface Weapon {
    int getCurrDurability();

    void setCurrDurability(int durability);

    Buff getBuff();
}
