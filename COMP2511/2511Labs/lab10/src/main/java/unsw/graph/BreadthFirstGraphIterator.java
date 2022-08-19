package unsw.graph;

import java.util.*;

public class BreadthFirstGraphIterator<N extends Comparable<N>> extends GraphSearch<N> {

    public BreadthFirstGraphIterator(Graph<N> graph, N first) {
        super(graph, first);
    }

    @Override
    public N next() {
        if (!hasNext()) return null;

        N node = queue.pollFirst();
        visited.add(node);
        List<N> adjacentNodes = graph.getAdjacentNodes(node);
        for (N adjNode : adjacentNodes) {
            if (!visited.contains(adjNode)) {
                visited.add(adjNode);
                queue.add(adjNode);
            }
        }
        return node;
    }
}