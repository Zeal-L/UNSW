package dungeonmania.ZombieBehavior;

import dungeonmania.Algorithm;
import dungeonmania.MovingEntities.ZombieToast;
import dungeonmania.util.Position;

public class Runaway implements ZombieBehavior {

    @Override
    public Position action(ZombieToast zombie) {
        return Algorithm.Away(zombie,zombie.getPlayerPosition());
    }
}
