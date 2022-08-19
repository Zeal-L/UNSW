package dungeonmania.CollectableEntities;

import dungeonmania.Game;
import dungeonmania.PlayerMode.Invisible;
import dungeonmania.Usable;
import dungeonmania.util.Position;

public class InvisibilityPotion extends CollectableEntities implements Usable {
    private static int MaxDuration;
    public InvisibilityPotion(int x, int y, String type) {
        super(type, false, new Position(x, y));
    }
    public static void setMaxDuration(int MaxDuration) {
        InvisibilityPotion.MaxDuration = MaxDuration;
    }

    @Override
    public void use() {
        Game.getGame().getPlayer().addMode(new Invisible(MaxDuration, getId(), getType()));
        Game.getGame().getPlayer().removeFromBag(getId());
    }
}
