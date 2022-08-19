package q15.expect;

public class Decorator<E> extends Expect<E> {
    private Expect<E> wrappee;

    public Decorator(Expect<E> wrappee) {
        this.wrappee = wrappee;
    }

    @Override 
    public void evaluate() {
        wrappee.evaluate();
    }
    
}
