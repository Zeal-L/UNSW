package dungeonmania.MercenaryBehavior;

import dungeonmania.MovingEntities.Mercenary;
import dungeonmania.util.Position;

public interface MercenaryBehavior {
    Position action(Mercenary mercenary);
}
