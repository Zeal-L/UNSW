package dungeonmania.BuildableEntities;

import dungeonmania.Buff;
import dungeonmania.Entity;
import dungeonmania.MovingEntities.Player;
import dungeonmania.Weapon;
import dungeonmania.exceptions.InvalidActionException;

import java.util.List;
import java.util.stream.Collectors;

public class Shield extends BuildableEntities implements Weapon {
    private static int defense;
    private static int durability;
    private int currentDurability;

    public Shield() {
        super("shield");
        currentDurability = durability;
    }

    public static void setDefense(int defense) {
        Shield.defense = defense;
    }

    public static void setDurability(int durability) {
        Shield.durability = durability;
    }

    public static boolean checkRecipe(List<Entity> backpack) {
        List<String> bag = backpack.stream().map(Entity::getType).collect(Collectors.toList());
        return bag.stream().filter(e -> e.startsWith("wood")).count() >= 2 && (bag.stream().anyMatch(e -> e.startsWith("treasure")) || bag.stream().anyMatch(e -> e.startsWith("key")));
    }

    public static void build(Player player) throws InvalidActionException {
        if (!checkRecipe(player.getBackpack()))
            throw new InvalidActionException("player does not have entity to build a shield");
        List<String> wood = player.getBackpack().stream().filter(e -> e.getType().startsWith("wood")).limit(2).map(Entity::getId).collect(Collectors.toList());
        wood.forEach(player::removeFromBag);
        player.removeFromBag(player.getBackpack().stream().filter(e -> e.getType().startsWith("treasure") || e.getType().startsWith("key")).map(Entity::getId).findFirst().get());
        player.addToBag(new Shield());
    }

    @Override
    public int getCurrDurability() {
        return currentDurability;
    }

    @Override
    public void setCurrDurability(int durability) {
        currentDurability = durability;
    }

    @Override
    public Buff getBuff() {
        return new Buff(0, 0, defense, getId(), getType());
    }
}
