package q14;

public interface Publisher<P extends Comparable<P>> {
    public void addSubscriber(Subscriber<P> s);
}
