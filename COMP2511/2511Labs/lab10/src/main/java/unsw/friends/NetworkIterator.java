package unsw.friends;

import java.util.Iterator;

public class NetworkIterator<P extends Comparable<P>> implements Iterator<P> {

    private Iterator<P> iter;

    public NetworkIterator(Iterator<P> iter) {
        this.iter = iter;
    }

    @Override
    public boolean hasNext() {
        return iter.hasNext();
    }

    @Override
    public P next() {
        return iter.next();
    }

}
