package unsw.jql.v1.decorator;

import unsw.jql.v1.TableView;

public class SkipDecorator<E> extends OperationDecorator<E, E> {

    private int numberOfItems;

    public SkipDecorator(TableView<E> inner, int numberOfItems) {
        super(inner);
        this.numberOfItems = numberOfItems;
    }

    @Override
    public boolean hasNext() {
        return super.count() > numberOfItems && super.hasNext();
    }

    @Override
    public E next() {
        while (numberOfItems > 0 && hasNext()) {
            numberOfItems--;
            super.nextElement();
        }

        return super.nextElement();
    }

    @Override
    public int count() {
        int innerCount = super.count();
        return (numberOfItems <= innerCount) ? (innerCount - numberOfItems) : innerCount;
    }
}