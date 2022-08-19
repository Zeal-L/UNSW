package unsw.hamper;

/**
 * The number of times an element occurs in the containing Hamper.
 * @author Matthew Perry
 *
 * @param <E> The generic element for which this is an occurrence count.
 */
public class Count<E> {
    
    private E e;
    
    private int count;
    
    /**
     * Create a Count with the given element and initial count
     * @param e
     */
    public Count(E e, int count) {
        this.e = e;
        this.count= count;
    }
    
    /**
     * Get the element
     * @return
     */
    public E getElement() {
        return e;
    }
    
    /**
     * Get the count
     * @return
     */
    public int getCount() {
        return count;
    }
    
    /**
     * Increment the count by the given amount
     * @param n
     */
    public void incrementCount(int n) {
        count += n;
    }
    
    /**
     * Decrement the count by the given amount
     * @param n
     */
    public void decrementCount(int n) {
        count -= n;
    }

    @Override
    public String toString(){
        return "Count: "+e.toString()+" appears "+count+" times";
    }
}
