package dungeonmania.CollectableEntities;

import dungeonmania.util.Position;

public class Treasure extends CollectableEntities {
    public Treasure(int x, int y, String type) {
        super(type, false, new Position(x, y));
    }
}
