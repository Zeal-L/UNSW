package q14;

public interface Subscriber<P extends Comparable<P>> {
    // updates subscribers about publisher changes
    public void update(WasteBookController<P> p);
}
