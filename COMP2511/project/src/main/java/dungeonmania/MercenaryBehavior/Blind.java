package dungeonmania.MercenaryBehavior;

import dungeonmania.Algorithm;
import dungeonmania.MovingEntities.Mercenary;
import dungeonmania.util.Position;

public class Blind implements MercenaryBehavior {
    @Override
    public Position action(Mercenary mercenary) {
        return Algorithm.RandomPosition(mercenary.getPosition(), mercenary);
    }
}
