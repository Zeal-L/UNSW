package dungeonmania.CollectableEntities;

import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;

import dungeonmania.Entity;
import dungeonmania.Game;
import dungeonmania.Usable;
import dungeonmania.MovingEntities.Player;
import dungeonmania.TiggerPublisher.TriggerPublisher;
import dungeonmania.TiggerPublisher.TriggerSubscriber;
import dungeonmania.util.Position;

public class Bomb extends CollectableEntities implements Usable, TriggerSubscriber {
    private static int bombRadius;
    private boolean isPlaced;

    public Bomb(int x, int y, String type) {
        super(type, false, new Position(x, y));
        isPlaced = false;
    }
    
    public static void setBombRadius(int bombRadius) {
        Bomb.bombRadius = bombRadius;
    }
    @Override
    public void triggerEffect(Entity entity) {
        // pick up and put into bag
        if (isPlaced) return;
        super.triggerEffect(entity);
    }
    @Override
    public void use() {
        isPlaced = true;
        setPosition(Game.getGame().getPlayer().getPosition());
        Game.getGame().getPlayer().removeFromBag(getId());
        List<TriggerPublisher> publisher = Game.cardinallyAdjacent(getPosition()).stream().map(e -> Game.getGame().findEntityByPosition(e).stream().filter(a -> a instanceof TriggerPublisher).collect(Collectors.toList())).
            flatMap(List::stream).map(e -> ((TriggerPublisher) e)).collect(Collectors.toList());
        setBlocked(true);
        if (publisher.stream().anyMatch(TriggerPublisher::isTriggered)) trigger();
        else publisher.forEach(e -> e.subscribe(this));
    }

    @Override
    public void trigger() {
        Object obj = ((ArrayList<Entity>) Game.getGame().findEntityInRange(getPosition(),bombRadius)).clone();
        Iterable<?> temp = (Iterable<?>) obj;

        ArrayList<Entity> entities = new ArrayList<>();
        temp.forEach(e -> entities.add((Entity) e));

        entities.stream()
            .filter(e -> !e.getClass().equals(Player.class))
            .forEach(Game.getGame()::removeEntity);
    }
}
