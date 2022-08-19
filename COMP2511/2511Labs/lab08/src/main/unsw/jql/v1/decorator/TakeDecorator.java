package unsw.jql.v1.decorator;

import java.util.NoSuchElementException;

import unsw.jql.v1.TableView;

public class TakeDecorator<E> extends OperationDecorator<E, E> {

    private int numOfItems;

    public TakeDecorator(TableView<E> inner, int numOfItems) {
        super(inner);
        this.numOfItems = numOfItems;
    }

    @Override
    public boolean hasNext() {
        return numOfItems > 0 && super.hasNext();
    }

    @Override
    public E next() throws NoSuchElementException {
        if (hasNext()) {
            numOfItems--;
            return super.nextElement();
        } else {
            throw new NoSuchElementException();
        }

    }

    @Override
    public int count() {
        int count = 0;
        while (hasNext()) {
            next();
            count++;
        }
        return count;
    }
}