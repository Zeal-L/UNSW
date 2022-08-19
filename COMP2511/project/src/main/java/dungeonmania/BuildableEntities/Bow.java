package dungeonmania.BuildableEntities;

import dungeonmania.Buff;
import dungeonmania.Entity;
import dungeonmania.MovingEntities.Player;
import dungeonmania.Weapon;
import dungeonmania.exceptions.InvalidActionException;

import java.util.List;
import java.util.stream.Collectors;

public class Bow extends BuildableEntities implements Weapon {
    private static int durability;
    private int currDurability;

    public Bow() {
        super("bow");
        currDurability = durability;
    }

    public static void setDurability(int durability) {
        Bow.durability = durability;
    }

    public static boolean checkRecipe(List<Entity> backpack) {
        List<String> bag = backpack.stream().map(Entity::getType).collect(Collectors.toList());
        return bag.stream().filter(e -> e.startsWith("arrow")).count() >= 3
                && bag.stream().anyMatch(e -> e.startsWith("wood"));
    }

    public static void build(Player player) throws InvalidActionException {
        if (!checkRecipe(player.getBackpack()))
            throw new InvalidActionException("player does not have entity to build a bow");
        List<String> woods = player.getBackpack().stream().filter(e -> e.getType().startsWith("arrow")).limit(3)
                .map(Entity::getId).collect(Collectors.toList());
        String arrows = player.getBackpack().stream().filter(e -> e.getType().startsWith("wood")).map(Entity::getId)
                .findFirst().orElse("");
        woods.forEach(player::removeFromBag);
        player.removeFromBag(arrows);
        player.addToBag(new Bow());
    }

    @Override
    public int getCurrDurability() {
        return currDurability;
    }

    @Override
    public void setCurrDurability(int durability) {
        currDurability = durability;
    }

    @Override
    public Buff getBuff() {
        return new Buff(0, 2, 0, getId(), getType());
    }
}
