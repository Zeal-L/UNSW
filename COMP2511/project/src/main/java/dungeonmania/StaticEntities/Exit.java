package dungeonmania.StaticEntities;

import dungeonmania.util.Position;

public class Exit extends StaticEntities {
    public Exit(int x, int y, String type) {
        super(type, false, false, new Position(x, y));
    }
}
