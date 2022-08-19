package q14;

import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;


public class Person<P extends Comparable<P>> {
    
    private List<Person<P>> following = new ArrayList<Person<P>>();
    private P id;

    public Person(P id) {
        this.id = id;
    }

    public P getId() {
        return id;
    }

    public List<Person<P>> getFollowing() {
        return following;
    }

    public List<Person<P>> getFriends() {
        return following.stream()
                        .filter(p -> p.getFollowing()
                        .contains(this))
                        .collect(Collectors.toList());
    }

    public void follow(Person<P> person) {
        following.add(person);
    }
    
    public boolean isFollowing(Person<P> person) {
        return following.contains(person);
    }

}