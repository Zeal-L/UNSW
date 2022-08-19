package dungeonmania;

import dungeonmania.util.Position;

import java.util.*;
import java.util.stream.Collectors;

public class Algorithm {
    public static List<Position> ShortestPath(Position start, Position end, Entity entity) {
        Queue<Position> queue = new LinkedList<>();
        queue.add(start);
        ArrayList<Position> visited = new ArrayList<>();
        Map<Position, Position> path = new java.util.HashMap<>();
        while (!queue.isEmpty()) {
            Position current = queue.remove();
            if (current.equals(end)) {
                ArrayList<Position> shortestPath = new ArrayList<>();
                while (!end.equals(start)) {
                    shortestPath.add(end);
                    end = path.get(end);
                }
                return shortestPath;
            }
            Game.cardinallyAdjacent(current).stream().
                    filter(e -> !visited.contains(e) &&
                            Game.getGame().findEntityByPosition(e).stream().noneMatch(a -> a.isBlocked(entity)) &&
                            Game.getGame().inMap(e))
                    .forEach(e -> {
                        visited.add(e);
                        queue.add(e);
                        path.put(e, current);
                    });
        }
        return new ArrayList<>();
    }

    public static Position RandomPosition(Position start, Entity entity) {
        List<Position> current = Game.cardinallyAdjacent(start).stream().
                filter(e -> Game.getGame().findEntityByPosition(e).stream().noneMatch(a -> a.isBlocked(entity))).
                collect(Collectors.toList());
        if (current.size() == 0) return start;
        return current.get(new Random().nextInt(current.size()));
    }

    public static Position Away(Entity entity, Position goal) {
        Map<Position, Double> distanceMap = new HashMap<>();
        Position currpos = entity.getPosition();
        List<Position> avliable = Game.cardinallyAdjacent(currpos).stream()
                .filter(e -> Game.getGame().findEntityByPosition(e).stream()
                        .noneMatch(a -> a.isBlocked(entity)))
                .collect(Collectors.toList());
        if (avliable.size() == 0) return currpos;
        avliable.forEach(position -> distanceMap.put(position, Game.getPreciseDistance(position, goal)));
        return distanceMap.entrySet().stream().max(Comparator.comparingDouble(Map.Entry::getValue)).get().getKey();
    }
}
