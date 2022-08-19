package dungeonmania.StaticEntities;

import java.util.Map;
import java.util.Objects;

import dungeonmania.Entity;
import dungeonmania.Game;
import dungeonmania.Triggerable;
import dungeonmania.MovingEntities.Mercenary;
import dungeonmania.MovingEntities.Player;
import dungeonmania.util.Position;

public class Portal extends StaticEntities implements Triggerable {
    private final String colour;
    public Portal(int x, int y, String colour, String type) {
        super(type+"_"+colour.toLowerCase(), true, false, new Position(x, y));
        this.colour = colour;
    }


    @Override
    public void triggerEffect(Entity entity) {
        if((! (entity instanceof Player) && ! (entity instanceof Mercenary))) return;
        Map<String,Position> pos = getTranslatedPosition(entity.getPosition());
        if(pos == null) return;
        entity.setPosition(pos.get("portal"));
        if(Game.getGame().findEntityByPosition(pos.get("translate")).stream().noneMatch(e -> e.isBlocked(entity))){
            Game.getGame().findEntityByPosition(pos.get("translate")).stream()
                    .filter(a -> a instanceof Triggerable)
                    .map(a -> ((Triggerable) a))
                    .forEach(e -> e.triggerEffect(entity));
            entity.setPosition(pos.get("translate"));
        } else {
            Game.cardinallyAdjacent(pos.get("portal")).stream().
                    filter(e -> Game.getGame().findEntityByPosition(e).size() == 0).
                    findFirst().ifPresent(entity::setPosition);
        }
    }
    @Override
    public boolean isBlocked(Entity entity) {
        if((!(entity instanceof Player) && !(entity instanceof Mercenary))) return true;
        Map<String,Position> pos = getTranslatedPosition(entity.getPosition());
        if(pos == null) return true;
        Position originPos = entity.getPosition();
        entity.setPosition(pos.get("portal"));
        if(Game.getGame().findEntityByPosition(pos.get("translate")).stream().anyMatch(e -> e.isBlocked(entity)) &&
                Game.cardinallyAdjacent(pos.get("portal")).stream().noneMatch(e -> Game.getGame().findEntityByPosition(e).size() == 0 || Game.getGame().findEntityByPosition(e).stream().noneMatch(a -> a.isBlocked(entity)))){
            entity.setPosition(originPos);
            return true;
        }
        entity.setPosition(originPos);
        return false;
    }
    public Map<String,Position> getTranslatedPosition(Position pos) {
        Portal p = Game.getGame().findEntityByType("portal").stream().map(e->(Portal) e).filter(e->e.getColour().equals(colour) && !Objects.equals(e.getId(), getId())).findFirst().orElse(null);
        if(p == null) return null;
        Position translateP = p.getPosition().translateBy(getPosition().getX()-pos.getX(), getPosition().getY()-pos.getY());
        if(Game.getGame().findEntityByPosition(translateP).stream().anyMatch(e -> e instanceof Portal)) {
            return Game.getGame().findEntityByPosition(translateP).stream().filter(e -> e instanceof Portal).map(e -> ((Portal) e)).findFirst().get().getTranslatedPosition(p.getPosition());
        } else {
            return Map.of("portal", p.getPosition(), "translate", translateP);
        }
    }
    public String getColour() {
        return colour;
    }
}
