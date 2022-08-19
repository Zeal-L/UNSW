package dungeonmania.MercenaryBehavior;

import dungeonmania.Algorithm;
import dungeonmania.Game;
import dungeonmania.MovingEntities.Mercenary;
import dungeonmania.util.Position;

import java.util.List;

public class Bribed implements MercenaryBehavior {
    @Override
    public Position action(Mercenary mercenary) {
        if (Game.getPreciseDistance(mercenary.getPosition(), mercenary.getPlayerPosition()) <= 1) {
            return mercenary.getPosition();
        }
        List<Position> shortestPath = Algorithm.ShortestPath(mercenary.getPosition(), mercenary.getPlayerPosition(), mercenary);
        if (shortestPath.size() != 0) {
            return shortestPath.get(shortestPath.size() - 1);
        }
        return mercenary.getPosition();
    }
}
