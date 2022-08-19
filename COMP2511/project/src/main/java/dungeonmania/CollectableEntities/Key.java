package dungeonmania.CollectableEntities;

import dungeonmania.util.Position;

public class Key extends CollectableEntities {
    private final int keyID;
    public Key(int x, int y, int keyID, String type) {
        super(type, false, new Position(x, y));
        this.keyID = keyID;
    }

    public int getKeyID() {
        return keyID;
    }
}
