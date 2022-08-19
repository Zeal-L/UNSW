package unsw.graph;

import java.util.Deque;
import java.util.HashSet;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.Set;

public abstract class GraphSearch <N extends Comparable<N>> implements Iterator<N> {
    protected Graph<N> graph;
    protected Deque<N> queue;
    protected Set<N> visited;

    public GraphSearch(Graph<N> graph, N first) {
        this.graph = graph;
        queue = new LinkedList<>();
        visited = new HashSet<>();
        queue.add(first);
        visited.add(first);
    }

    @Override
    public boolean hasNext() {
        return !queue.isEmpty();
    }

}
