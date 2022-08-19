package unsw.jql.v1.decorator;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

import unsw.jql.v1.Table;
import unsw.jql.v1.TableView;

public abstract class OperationDecorator<E, R> implements TableView<R> {

    private TableView<E> inner;

    public OperationDecorator(TableView<E> inner) {
        this.inner = inner;
    }

    @Override
    public boolean hasNext() {
        return inner.hasNext();
    }

    @Override
    public abstract R next();

    public E nextElement() {
        return inner.next();
    }

    @Override
    public Iterator<R> iterator() {
        return this;
    }

    @Override
    public int count() {
        return inner.count();
    }

    @Override
    public Table<R> toTable() {
        List<R> list = new ArrayList<R>();
        this.forEachRemaining(list::add);
        return new Table<R>(list);
    }
    
}