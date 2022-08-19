package unsw.friends;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.stream.Collectors;

public class WasteBookController<P extends Comparable<P>> {
    
    List<Person<P>> people = new ArrayList<Person<P>>();
    /**
     * Adds a new member with the given name to the network. 
     */
    public void addPersonToNetwork(P name) {
        people.add(new Person<P>(name));
    }

    /**
     * @preconditions person1 and person2 already exist in the social media network.
     * person1 follows person2 in the social media network.
     */
    public void follow(P person1, P person2) {
        if (person1.equals(person2)) {
            return;
        }

        for (Person<P> member1 : people) {
            if (member1.getId().equals(person1)) {
                for (Person<P> member2 : people) {
                    if (member2.getId().equals(person2)) {
                        List<Person<P>> following = member1.getFollowing();
                        following.add(member2);

                        if (member2.isFollowing(member1)) {
                            member1.addFriend(member2);
                            member2.addFriend(member1);
                        }
                    }
                }
            }
        }
    }

    public int getPopularity(P person) {
        Person<P> member = people.stream().filter(p -> p.getId().equals(person)).findFirst().get();
        int popularity = 0;

        for (Person<P> other : people) {
            List<Person<P>> following = other.getFollowing();
            if (following.contains(member)) {
                popularity += 1;
            }
        }

        return popularity;
    }

    public int getFriends(P person) {
        Person<P> member = people.stream().filter(p -> p.getId().equals(person)).findFirst().get();
        return member.getFriends().size();
    }

    /**
     * Returns an iterator to the network (each member)
     * ordered by the given parameter.
     */
    public NetworkIterator<P> getIterator(String orderBy) {
        Comparator<Person<P>> comparator = null;
        if (orderBy.equals("popularity")) {
            comparator = Comparator.comparing(p -> -getPopularity(p.getId()));
        } else if (orderBy.equals("friends")) {
            comparator = Comparator.comparing(p -> -getFriends(p.getId()));
        }

        comparator = comparator.thenComparing(Person::getId);

        return new NetworkIterator<P>(people.stream()
                     .sorted(comparator)
                     .map(Person::getId)
                     .collect(Collectors.toList())
                     .iterator());
    }

    public void switchIteratorComparisonMethod(NetworkIterator<P> iter, String orderBy) {
        // TODO Part d)
    }
}