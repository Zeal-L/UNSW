package q15.expect;

public class SkipDecorator<E> extends Decorator<E> {

    public SkipDecorator(Expect<E> wrappee) {
        super(wrappee);
    }
    
    @Override 
    public void evaluate() {
        super.evaluate();
    }
    
}
