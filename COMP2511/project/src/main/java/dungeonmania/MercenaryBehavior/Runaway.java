package dungeonmania.MercenaryBehavior;

import dungeonmania.Algorithm;
import dungeonmania.MovingEntities.Mercenary;
import dungeonmania.util.Position;

public class Runaway implements MercenaryBehavior {

    @Override
    public Position action(Mercenary mercenary) {
        return Algorithm.Away(mercenary, mercenary.getPlayerPosition());
    }
}
