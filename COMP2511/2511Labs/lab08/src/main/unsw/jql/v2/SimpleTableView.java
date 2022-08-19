package unsw.jql.v2;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Iterator;
import java.util.List;
import java.util.NoSuchElementException;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.ForkJoinPool;
import java.util.concurrent.Future;
import java.util.function.BiFunction;
import java.util.function.BinaryOperator;
import java.util.function.Function;
import java.util.function.Predicate;

public class SimpleTableView<E> implements TableView<E> {
    private Iterator<E> it;

    public SimpleTableView() {
        this(Arrays.<E>asList().iterator());
    }

    public SimpleTableView(Iterator<E> it) {
        this.it = it;
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
    public TableView<E> take(int numberOfItems) {
        SimpleTableView<E> parent = this;

        return new SimpleTableView<E>() {
            private int itemsLeft = numberOfItems;

            @Override
            public boolean hasNext() {
                return itemsLeft > 0 && parent.hasNext();
            }

            @Override
            public E next() {
                if (hasNext()) {
                    itemsLeft--;
                    return parent.next();
                } else
                    throw new NoSuchElementException();
            }
        };
    }

    @Override
    public TableView<E> skip(int numberOfItems) {
        while (numberOfItems > 0 && hasNext()) {
            numberOfItems--;
            next();
        }
        return this;
    }

    @Override
    public Table<E> toTable() {
        List<E> list = new ArrayList<E>();
        it.forEachRemaining(list::add);
        return new Table<E>(list);
    }

    @Override
    public Iterator<E> iterator() {
        // *technically* this is non standard
        // since this should reproduce a unique iterator each time
        // but for our sakes it's fine, since any operation on an
        // iterator will implicitly invalidate the inner iterators
        // invalidating it's original context anyways.
        return this;
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

    @Override
    public <R> TableView<R> select(Function<E, R> selector) {
        // TODO Task 5)
        return new SimpleTableView<R>() {
            @Override
            public boolean hasNext() {
                return SimpleTableView.this.hasNext();
            }
    
            @Override
            public R next() {
                return selector.apply(SimpleTableView.this.next());
            }
        };
    }

    @Override
    public TableView<E> where(Predicate<E> pred) {
        // TODO Task 6) - Choice
        return null;
    }

    @Override
    public <R> R reduce(BiFunction<R, E, R> reducer, R initial) {
        synchronized (reducer) {
            while (hasNext()) {
                initial = reducer.apply(initial, next());
            }
        }
        return initial;
    }

    @Override
    public <R> R parallelReduce(BiFunction<R, E, R> reducer, BinaryOperator<R> combiner, R initial,
            int numberOfThreads) throws InterruptedException, ExecutionException {
        // you don't have to change this function at all.

        // create a pool of threads to pick jobs.
        ForkJoinPool pool = new ForkJoinPool(numberOfThreads);
        Callable<R> reductionOperation = () -> reduce((acc, cur) -> reducer.apply(acc, cur), initial);

        // fully exhaust pool
        List<Callable<R>> callables = new ArrayList<>();
        for (int i = 0; i < numberOfThreads; i++)
            callables.add(reductionOperation);

        // execute all the operations, this is the concurrency part (this single
        // function call)
        List<Future<R>> results = pool.invokeAll(callables);

        // at this point we are single threaded and can just accumulate the left over
        // values
        R accValue = initial;
        for (Future<R> result : results) {
            accValue = combiner.apply(accValue, result.get());
        }

        return accValue;
    }
}
