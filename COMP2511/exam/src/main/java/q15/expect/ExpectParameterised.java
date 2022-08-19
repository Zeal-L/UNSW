package q15.expect;

import java.util.Iterator;
import java.util.List;
import java.util.function.Consumer;

public class ExpectParameterised<T, C extends Consumer<T>, L extends List<T>> implements Iterable<Runnable> {

    public ExpectParameterised(C consumer, L parameters) {

    }

    @Override
    public Iterator<Runnable> iterator() {
        return null;
    }

    public void evaluateAll() throws Throwable {

    }

}