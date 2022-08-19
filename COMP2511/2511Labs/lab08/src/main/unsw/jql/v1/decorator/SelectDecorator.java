package unsw.jql.v1.decorator;

import java.util.function.Function;

import unsw.jql.v1.TableView;

public class SelectDecorator<E, R> extends OperationDecorator<E, R> {

    private Function<E, R> selector;
    private TableView<E> inner;

    public SelectDecorator(TableView<E> inner, Function<E, R> selector) {
        super(inner);
        this.inner = inner;
        this.selector = selector;
    }

    @Override
    public R next() {
        return selector.apply(inner.next());
    }
    
}