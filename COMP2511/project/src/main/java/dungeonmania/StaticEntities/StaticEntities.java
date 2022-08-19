package dungeonmania.StaticEntities;

import dungeonmania.Entity;
import dungeonmania.util.Position;

public abstract class StaticEntities extends Entity {

    public StaticEntities(String type, boolean isBlocked, boolean isInteractable, Position position) {
        super(type, isBlocked, isInteractable, position);
    }
}
