package dungeonmania.StaticEntities;

import dungeonmania.Entity;
import dungeonmania.Game;
import dungeonmania.MovingEntities.Player;
import dungeonmania.Triggerable;
import dungeonmania.util.Position;

import java.util.List;

public class Boulder extends StaticEntities implements Triggerable {
    public Boulder(int x, int y, String type) {
        super(type, true, false, new Position(x, y));
    }
    @Override
    public void triggerEffect(Entity entity) {
        
        if(entity instanceof Player) {
            Game.getGame().findEntityByPosition(getPosition()).stream()
                    .filter(a -> a instanceof FloorSwitch)
                    .map(a -> ((FloorSwitch) a))
                    .forEach(e -> e.setIsOn(false));
            setPosition(forwardPosition(entity));
            Game.getGame().findEntityByPosition(getPosition()).stream()
                    .filter(a -> a instanceof Triggerable)
                    .map(a -> ((Triggerable) a))
                    .forEach(e -> e.triggerEffect(this));
        }
    }
    @Override
    public boolean isBlocked(Entity entity) {
        if (entity instanceof Player) {
            List<Entity> entities = Game.getGame().findEntityByPosition(forwardPosition(entity));
            if (entities.stream().anyMatch(e -> e instanceof Boulder)) {
                return true;
            } 
            return entities.stream().anyMatch(e -> e.isBlocked(this));
        } 
        return true;
    }

    private Position forwardPosition(Entity entity) {
        if (entity.getPosition().getX() == this.getPosition().getX()) {
            return new Position(
                entity.getPosition().getX(), 
                getPosition().getY() + (getPosition().getY() < entity.getPosition().getY() ? -1 : 1)
            );
        } else if (entity.getPosition().getY() == this.getPosition().getY()) {
            return new Position(
                getPosition().getX() + (getPosition().getX() < entity.getPosition().getX() ? -1 : 1),
                entity.getPosition().getY()
            );
        } else {
            return entity.getPosition();
        } 
    }

}
