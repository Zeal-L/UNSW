package dungeonmania.CollectableEntities;

import dungeonmania.Entity;
import dungeonmania.Triggerable;
import dungeonmania.MovingEntities.Player;
import dungeonmania.util.Position;

public abstract class CollectableEntities extends Entity implements Triggerable {
    public CollectableEntities(String type, boolean isBlocked, Position position) {
        super(type, isBlocked, false, position);
    }

    @Override
    public void triggerEffect(Entity entity) {
        // pick up and put into bag
        if(entity instanceof Player) {
            ((Player) entity).addToBag(this);
            this.setPosition(notInMap);
        }
    }
}
