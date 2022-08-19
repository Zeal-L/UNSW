package dungeonmania;


import dungeonmania.util.Position;

public abstract class Entity {
    public static final Position notInMap = null;
    public static int IdCounter = 0;
    private final String id;
    private final String type;
    private final boolean isInteractable;
    private Position position;
    private boolean isBlocked;

    public Entity(String type, boolean isBlocked, boolean isInteractable, Position position) {
        this.id = String.valueOf(IdCounter++);
        this.isInteractable = isInteractable;
        this.type = type;
        this.position = position;
        this.isBlocked = isBlocked;
    }

    public static void resetIdCounter() {
        IdCounter = 0;
    }

    public boolean isInteractable() {
        return isInteractable;
    }

    public String getId() {
        return id;
    }

    public String getType() {
        return type;
    }

    public Position getPosition() {
        return position;
    }

    public void setPosition(Position position) {
        this.position = position;
    }

    public boolean isBlocked(Entity entity) {
        return isBlocked;
    }

    public void setBlocked(boolean blocked) {
        isBlocked = blocked;
    }
}
