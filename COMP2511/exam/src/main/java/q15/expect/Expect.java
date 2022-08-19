package q15.expect;

public class Expect<E> {
    
    private E inner;

    private boolean check;

    protected Expect() {}

    public Expect(E obj) {
        this.inner = obj;
    }

    public void setCheck(boolean check) {
        this.check = check;
    }

    public boolean getCheck() {
        return check;
    }

    public Expect<E> toEqual(E other) {
        Expect<E> result = new Expect<E>(this.inner);
        result.setCheck(this.inner.equals(other));
        return result;
    }

    public<T extends Comparable<E>> Expect<E> lessThan(T other) {
        Expect<E> result = new Expect<E>(this.inner);
        result.setCheck(this.inner.hashCode() < other.hashCode());
        return result;
    }

    public<T extends Comparable<E>> Expect<E> greaterThanOrEqualTo(T other) {
        Expect<E> result = new Expect<E>(this.inner);
        result.setCheck(this.inner.hashCode() >= other.hashCode());
        return result;
    }

    public Expect<E> not() {
        Expect<E> result = new Expect<E>(this.inner);
        result.setCheck(!this.check);
        return new NotDecorator<E>(result);
    }

    public Expect<E> skip() {
        Expect<E> result = new Expect<E>(this.inner);
        return new SkipDecorator<E>(result);
    }

    public void evaluate() {
        if (!this.check) {
            throw new ExpectationFailedException(null);
        }
    }

    protected E getInner() {
        return inner;
    }

}