package q15.expect;

public class ExpectRunnable<E extends Runnable> extends Expect<E> {

    public ExpectRunnable(E exec) {

    }

    public<X extends Exception> ExpectRunnable<E> toThrow(Class<X> clz) {
        return null;
    }
    
    public void execute() throws Throwable {

    }
}