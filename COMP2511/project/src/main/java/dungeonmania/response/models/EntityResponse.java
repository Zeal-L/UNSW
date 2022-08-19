package dungeonmania.response.models;

import dungeonmania.util.Position;

public final class EntityResponse {
    private final String id;
    private final String type;
    private final Position position;
    private final boolean isInteractable;

    public EntityResponse(String id, String type, Position position, boolean isInteractable) {
        this.id = id;
        this.type = type;
        this.position = position;
        this.isInteractable = isInteractable;
    }

    public boolean isInteractable() {
        return isInteractable;
    }

    public final String getId() {
        return id;
    }

    public final String getType() {
        return type;
    }

    public final Position getPosition() {
        return position;
    }

    @Override
    public boolean equals(Object obj) {
        if (obj == this) return true;
        if (obj == null) return false;
        if (obj.getClass() != getClass()) return false;

        EntityResponse entityResponse = (EntityResponse) obj;
        return entityResponse.id.equals(id) &&
               entityResponse.type.equals(type) && 
               entityResponse.position.equals(position) &&
               entityResponse.isInteractable == isInteractable;
    }
}
