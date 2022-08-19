package dungeonmania.CollectableEntities;

import dungeonmania.Game;
import dungeonmania.PlayerMode.Invincible;
import dungeonmania.Usable;
import dungeonmania.util.Position;

public class InvincibilityPotion extends CollectableEntities implements Usable {
    private static int MaxDuration;
    public InvincibilityPotion(int x, int y, String type) {
        super(type, false, new Position(x, y));
    }
    public static void setMaxDuration(int MaxDuration) {
        InvincibilityPotion.MaxDuration = MaxDuration;
    }

    @Override
    public void use() {
        Game.getGame().getPlayer().addMode(new Invincible(MaxDuration, getId(), getType()));
        Game.getGame().getPlayer().removeFromBag(getId());
    }
}
