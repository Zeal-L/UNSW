package dungeonmania.MovingEntities;

import dungeonmania.Entity;
import dungeonmania.Game;
import dungeonmania.StaticEntities.Boulder;
import dungeonmania.Triggerable;
import dungeonmania.util.Position;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Map;

public class Spider extends MovingEntities implements Triggerable {
    private static double maxHealth;
    private static double maxAttack;
    private static int SpawnRate;
    private static int LastSpawn;
    private final Position birth;
    private boolean clockwise;

    public Spider(int x, int y, String type) {
        super(type, false, false, new Position(x, y), maxAttack, maxHealth);
        birth = new Position(x, y);
        clockwise = true;
    }
    public Spider(int x, int y) {
        this(x, y, "spider");
    }

    public static void setMaxHealth(double maxHealth) {
        Spider.maxHealth = maxHealth;
    }

    public static void setMaxAttack(double maxAttack) {
        Spider.maxAttack = maxAttack;
    }

    public static void setSpawnRate(int SpawnRate) {
        Spider.SpawnRate = SpawnRate;
        LastSpawn = 1;
    }

    public static void spawner() {
        if (SpawnRate == 0) return;
        LastSpawn++;
        if (LastSpawn <= SpawnRate) return;
        LastSpawn = 1;
        Map<String, Integer> MapSize = Game.getGame().getMapSize();
        while (true) {
            int x = (int) (Math.random() * MapSize.get("MaxMapX") + MapSize.get("MinMapX"));
            int y = (int) (Math.random() * MapSize.get("MaxMapY") + MapSize.get("MinMapY"));
            if (Game.getGame().findEntityByPosition(new Position(x, y)).stream().noneMatch(e -> e instanceof Player)) {
                Game.getGame().addEntity(new Spider(x, y));
                break;
            }
        }
    }

    @Override
    public void triggerEffect(Entity entity) {
        if (entity instanceof Player) {
            Game.getGame().newBattle(this, this.getType(), this.getId());
        }
    }

    @Override
    public void move() {
        if (Game.getGame().findEntityByPosition(getPosition()).stream().anyMatch(e -> e instanceof Boulder)) return;
        List<Position> path = clockwise ? pathClockWise() : pathNotClockWise();
        int i = path.indexOf(getPosition());
        Position next = path.get((i + 1) % path.size());
        if (Game.getGame().findEntityByPosition(next).stream().anyMatch(e -> e instanceof Boulder)) {
            clockwise = !clockwise;
            move();
            return;
        }
        Game.getGame().findEntityByPosition(next).stream().filter(a -> a instanceof Triggerable).map(a -> ((Triggerable) a)).forEach(e -> e.triggerEffect(this));
        Game.getGame().findEntityByPosition(next).forEach(e -> this.triggerEffect(e));
        setPosition(next);
    }

    private List<Position> pathClockWise() {
        return Arrays.asList(
                birth.translateBy(0, -1),
                birth.translateBy(1, -1),
                birth.translateBy(1, 0),
                birth.translateBy(1, 1),
                birth.translateBy(0, 1),
                birth.translateBy(-1, 1),
                birth.translateBy(-1, 0),
                birth.translateBy(-1, -1));
    }

    private List<Position> pathNotClockWise() {
        List<Position> path = pathClockWise();
        Collections.reverse(path);
        return path;
    }
}
