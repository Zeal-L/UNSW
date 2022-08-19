package dungeonmania.CollectableEntities;

import dungeonmania.util.Position;

public class Arrows extends CollectableEntities {
    public Arrows(int x, int y, String type) {
        super(type, false, new Position(x, y));
    }
}
