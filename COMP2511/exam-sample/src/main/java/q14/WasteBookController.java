package q14;

import java.util.ArrayList;
import java.util.List;

public class WasteBookController<P extends Comparable<P>> implements Publisher<P> {

    List<Person<P>> people = new ArrayList<Person<P>>();
    List<Subscriber<P>> iterators = new ArrayList<>();

    /**
     * Adds a new member with the given name to the network.
     */
    public void addPersonToNetwork(P name) {
        people.add(new Person<P>(name));
        iterators.forEach(it -> it.update(this));
    }

    public void addSubscriber(Subscriber<P> s) {
        iterators.add(s);
    }

    /**
     * @preconditions person1 and person2 already exist in the social media network.
     *                person1 follows person2 in the social media network.
     */
    public void follow(P person1, P person2) {
        if (person1.equals(person2)) {
            return;
        }
        getPerson(person1).follow(getPerson(person2));
    }

    public Person<P> getPerson(P person) {
        return people.stream().filter(p -> p.getId().equals(person)).findFirst().get();
    }

    public int getPopularity(P person) {
        return (int) people.stream().filter(p -> p.isFollowing(getPerson(person))).count();
    }

    public int getFriends(P person) {
        return getPerson(person).getFriends().size();
    }

    public List<Person<P>> getPeople() {
        return people;
    }

    /**
     * Returns an iterator to the network (each member)
     * ordered by the given parameter.
     */
    public NetworkIterator<P> getIterator(String orderBy) {
        NetworkIterator<P> it = new NetworkIterator<P>(this, orderBy);
        iterators.add(it);
        return it;

    }

    public void switchIteratorComparisonMethod(NetworkIterator<P> iter, String orderBy) {
        iter.setSortingStrategy(orderBy);
    }
}