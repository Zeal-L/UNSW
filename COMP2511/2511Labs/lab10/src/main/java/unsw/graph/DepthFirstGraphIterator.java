package unsw.graph;

import java.util.*;

public class DepthFirstGraphIterator<N extends Comparable<N>> extends GraphSearch<N> {

    public DepthFirstGraphIterator(Graph<N> graph, N first) {
        super(graph, first);
    }

    @Override
    public N next() {
        if (!hasNext()) return null;

        N node = queue.pollLast();
        visited.add(node);
        List<N> adjacentNodes = graph.getAdjacentNodes(node);
        adjacentNodes.sort(Collections.reverseOrder());
        for (N adjNode : adjacentNodes) {
            if (!visited.contains(adjNode)) {
                visited.add(adjNode);
                queue.add(adjNode);
            }
        }
        return node;
    }
}