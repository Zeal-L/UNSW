package dungeonmania.StaticEntities;

import dungeonmania.Entity;
import dungeonmania.Triggerable;
import dungeonmania.CollectableEntities.Key;
import dungeonmania.MovingEntities.Player;
import dungeonmania.util.Position;

public class Door extends StaticEntities implements Triggerable {
    private final int keyID;
    private boolean isClosed;

    public Door(int x, int y, int keyID, String type) {
        super(type, true, false, new Position(x, y));
        this.keyID = keyID;
        isClosed = true;
    }

    @Override
    public void triggerEffect(Entity entity) {
        if (entity instanceof Player && isClosed) {
            Player player = ((Player) entity);
            player.removeFromBag(player.getBackpack()
                    .stream()
                    .filter(e -> e instanceof Key)
                    .map(e -> ((Key) e)).filter(e -> e.getKeyID() == keyID)
                    .findFirst().get().getId());
            isClosed = false;
        }
    }

    @Override
    public boolean isBlocked(Entity entity) {
        return entity instanceof Player && isClosed ? ((Player) entity).getBackpack().stream()
                .filter(e -> e instanceof Key).map(e -> ((Key) e)).noneMatch(e -> e.getKeyID() == keyID) : isClosed;
    }
}