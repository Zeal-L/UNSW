package unsw.friends;

import java.util.ArrayList;
import java.util.List;

public class Person<P extends Comparable<P>> {
    
    private List<Person<P>> following = new ArrayList<Person<P>>();
    private List<Person<P>> friends = new ArrayList<Person<P>>();
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
        return friends;
    }
    
    public boolean isFollowing(Person<P> person) {
        return following.contains(person);
    }


    public void addFriend(Person<P> person) {
        friends.add(person);
    }
}