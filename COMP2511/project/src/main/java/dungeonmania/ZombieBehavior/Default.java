package dungeonmania.ZombieBehavior;

import dungeonmania.Algorithm;
import dungeonmania.MovingEntities.ZombieToast;
import dungeonmania.util.Position;

public class Default implements ZombieBehavior{

    @Override
    public Position action(ZombieToast zombie) {
        return Algorithm.RandomPosition(zombie.getPosition(), zombie);
    }
}
