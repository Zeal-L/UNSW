package dungeonmania.BuildableEntities;

import dungeonmania.Entity;

public abstract class BuildableEntities extends Entity {
    public BuildableEntities(String type) {
        super(type, false, false, notInMap);
    }
}
