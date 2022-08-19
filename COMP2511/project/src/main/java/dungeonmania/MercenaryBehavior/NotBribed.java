package dungeonmania.MercenaryBehavior;

import java.util.List;

import dungeonmania.Algorithm;
import dungeonmania.MovingEntities.Mercenary;
import dungeonmania.util.Position;

public class NotBribed implements MercenaryBehavior {
    @Override
    public Position action(Mercenary mercenary) {
        List<Position> shortestPath = Algorithm.ShortestPath(mercenary.getPosition(), mercenary.getPlayerPosition(), mercenary);
        if (shortestPath.size() != 0) {
            return shortestPath.get(shortestPath.size() - 1);
        } else {
            mercenary.setPosition(Algorithm.RandomPosition(mercenary.getPosition(), mercenary));
        }
        return mercenary.getPosition();
    }
}
