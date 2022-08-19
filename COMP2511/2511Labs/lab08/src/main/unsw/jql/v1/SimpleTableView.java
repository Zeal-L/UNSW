package unsw.jql.v1;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

public class SimpleTableView<E> implements TableView<E> {
    private Iterator<E> it;
    private List<E> temp_it;
    

    public SimpleTableView(List<E> list) {
        this.it = list.iterator();
        temp_it = list;
    }

    @Override
    public boolean hasNext() {
        return it.hasNext();
    }

    @Override
    public E next() {
        return it.next();
    }

    @Override
    public Table<E> toTable() {
        List<E> list = new ArrayList<E>();
        this.forEachRemaining(list::add);
        return new Table<E>(list);
    }

    @Override
    public Iterator<E> iterator() {
        // *technically* this is non standard
        // since this should reproduce a unique iterator each time
        // but for our sakes it's fine, since any operation on an
        // iterator will implicitly invalidate the inner iterators
        // invalidating its original context anyways.
        return this.it;
    }

    @Override
    public int count() {
        int count = 0;
        Iterator<E> iter = temp_it.iterator();
        while (iter.hasNext()) {
            iter.next();
            count++;
        }

        return count;
    }
}
