package dungeonmania.StaticEntities;

import java.util.List;
import java.util.Random;
import java.util.stream.Collectors;

import dungeonmania.Game;
import dungeonmania.Interactive;
import dungeonmania.CollectableEntities.Sword;
import dungeonmania.MovingEntities.Player;
import dungeonmania.MovingEntities.ZombieToast;
import dungeonmania.exceptions.InvalidActionException;
import dungeonmania.util.Position;

public class ZombieToastSpawner extends StaticEntities implements Interactive {
    private static int spawnRate;

    private int spawnCounter;

    public ZombieToastSpawner(int x, int y, String type) {
        super(type, false, true, new Position(x, y));
        spawnCounter = 1;
    }
    
    public static int getSpawnRate() {
        return spawnRate;
    }
    public static void setSpawnRate(int spawnRate) {
        ZombieToastSpawner.spawnRate = spawnRate;
    }

    
    public void spawn() {
        if(spawnRate == 0) return;
        if (spawnCounter < spawnRate) {
            spawnCounter++;
            return;
        }
            
        List<Position> current = Game.cardinallyAdjacent(getPosition()).stream()
            .filter(e -> Game.getGame().findEntityByPosition(e).size() == 0)
            .collect(Collectors.toList());
        
        if(current.size() == 0) return;
        Position newZombie = current.get(new Random().nextInt(current.size()));
        ZombieToast zt = new ZombieToast(newZombie.getX(), newZombie.getY());
        Game.getGame().getPlayer().subscribe(zt);
        Game.getGame().addEntity(zt);
        spawnCounter = 1;
    }
    
    @Override
    public void interact() throws InvalidActionException {
        Player player = Game.getGame().getPlayer();
        Position playerPosition = player.getPosition();
        
        if ((player.getBackpack().stream().anyMatch(e -> e instanceof Sword) &&
            (Game.cardinallyAdjacent(getPosition()).stream()
            .anyMatch(position -> position.equals(playerPosition))))) {
                Game.getGame().removeEntity(this);
                setPosition(notInMap);
        } else {
            throw new InvalidActionException("Criteria to destroy spawner is not fulfilled");
        }
    }
}
