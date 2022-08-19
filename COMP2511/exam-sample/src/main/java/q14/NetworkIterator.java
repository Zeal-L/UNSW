package q14;

import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Set;

public class NetworkIterator<P extends Comparable<P>>
        implements Iterator<P>, Subscriber<P> {

    private List<Person<P>> people;
    private Set<P> visited = new HashSet<>();
    private WasteBookController<P> controller;
    private SortingStrategy<P> strategy;

    public NetworkIterator(WasteBookController<P> p, String orderBy) {
        p.addSubscriber(this);
        this.controller = p;
        this.people = controller.getPeople();
        setSortingStrategy(orderBy);
    }

    public void setSortingStrategy(String orderBy) {
        if (orderBy.equals("popularity")) {
            strategy = new PopularityStrategy<P>();
        } else if (orderBy.equals("friends")) {
            strategy = new FriendsStrategy<P>();
        }
    }

    @Override
    public boolean hasNext() {
        return visited.size() < people.size();
    }

    @Override
    public P next() {
        List<Person<P>> sorted = strategy.sort(controller, people);
        P nextId = sorted
                .stream()
                .filter(p -> !visited.contains(p.getId()))
                .map(Person::getId)
                .findFirst()
                .orElse(null);

        visited.add(nextId);
        return nextId;
    }

    public void update(WasteBookController<P> p) {
        this.controller = p;
        this.people = controller.getPeople();
    }
}
