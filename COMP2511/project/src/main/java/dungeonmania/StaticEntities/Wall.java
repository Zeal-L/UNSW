package dungeonmania.StaticEntities;

import dungeonmania.util.Position;

public class Wall extends StaticEntities {
    public Wall(int x, int y, String type) {
        super(type, true, false, new Position(x, y));
    }
}
