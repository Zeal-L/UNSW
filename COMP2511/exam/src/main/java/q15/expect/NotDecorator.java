package q15.expect;

public class NotDecorator<E> extends Decorator<E> {

    public NotDecorator(Expect<E> wrappee) {
        super(wrappee);
    }
    
    @Override 
    public void evaluate() {
        super.setCheck(! super.getCheck());
        super.evaluate();
    }
    
}
