package dungeonmania.CollectableEntities;

import dungeonmania.util.Position;

public class Wood extends CollectableEntities {
    public Wood(int x, int y, String type) {
        super(type, false, new Position(x, y));
    }
}
