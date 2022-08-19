package dungeonmania.ZombieBehavior;

import dungeonmania.MovingEntities.ZombieToast;
import dungeonmania.util.Position;

public interface ZombieBehavior {
    Position action(ZombieToast zombie);
}
