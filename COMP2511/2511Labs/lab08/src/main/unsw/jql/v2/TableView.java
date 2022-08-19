package unsw.jql.v2;

import java.util.Iterator;
import java.util.concurrent.ExecutionException;
import java.util.function.BiFunction;
import java.util.function.BinaryOperator;
import java.util.function.Function;
import java.util.function.Predicate;

public interface TableView<E> extends Iterator<E>, Iterable<E> {
    /**
     * Grab a subset of the table view
     * @param numberOfItems The number of items to take, the rest are ignored
     */
    public TableView<E> take(int numberOfItems);

    /**
     * Grab a subset of the table view
     * @param numberOfItems The number of items to skip, the rest are taken
     */
    public TableView<E> skip(int numberOfItems);

    /**
     * Count number of records left
     */
    public int count();

    /**
     * Map a table view to another table view.
     * 
     * Each item/record is mapped through the provided selector.
     * 
     * An example would be `select((fruit) -> fruit.age())`
     */
    public<R> TableView<R> select(Function<E, R> selector);

    /**
     * Filter a table view to another table view which contains a subset of the records.
     * 
     * Each item/record is passed through the filter, if the function returns true then the record is kept
     * otherwise it is excluded.
     * 
     * An example would be `filter((fruit) -> fruit.age < 5)`
     */
    public TableView<E> where(Predicate<E> pred);

    /**
     * Reduce the view into a value.
     * 
     * For example the `sum` method for Fruit ages would look like;
     * `select(Fruit::age).reduce((acc, age) -> acc + age, 0)`
     * 
     * reducer:
     *  - First argument is the current accumulated value
     *  - Second argument is the next item in the stream
     *  - Should return the next accumulated value.
     * 
     * For example applying sum over ages (1, 2, 3, 4) is equal to
     * ((((0 + 1) + 2) + 3) + 4)
     */
    public <R> R reduce(BiFunction<R, E, R> reducer, R initial);

    /**
     * Apply reduce over multiple threads at once.  This function has been written for you
     * but since your reduce isn't likely threadsafe you'll want to modify your reduce to make
     * it work with parallel reduce.
     */
    public <R> R parallelReduce(BiFunction<R, E, R> reducer, BinaryOperator<R> combiner, R initial, int numberOfThreads) throws InterruptedException, ExecutionException;

    /**
     * Convert the remaining records into a table.
     */
    public Table<E> toTable();
}
