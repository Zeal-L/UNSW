package unsw.hamper;

import java.util.Iterator;

/**
 * Interface for a Hamper. A hamper is similar to a set but allows for
 * duplicates.
 *
 * @author Matthew Perry
 */
public interface Hamper<E> extends Iterable<Count<E>> {

	/**
	 * Adds a single copy of an element to the hamper
	 * @param e The element to add
	 * @postcondition count(e) = old count(e) + 1 OR count(e) = old count(e) if invariants would be violated by adding item
	 */
	public void add(E e);

	/**
	 * Adds multiple copies of an element to the hamper.
	 * @param e The element to add
	 * @param n The number of copies
	 * @precondition n >= 0
     * @postcondition count(e) = old count(e) + n OR count(e) = old count(e) if invariants would be violated by adding item
	 */
	public void add(E e, int n);

	/**
	 * Remove one copy of the given element from the hamper.
	 * @param e
     * @postcondition count(e) = max(old count(e) - 1, 0)
	 */
	public void remove(E e);

	/**
     * Remove multiple copies of an element from the hamper, or all copies if there
     * are not that many copies in the hamper.
     * @param e The element to remove
     * @param n The number of copies to remove.
     * @precondition n >= 0
     * @postcondition count(e) = max(old count(e) - n, 0)
     */
    public void remove(E e, int n);

    /**
     * Returns the number of times the given object occurs in the hamper
     * @param o The object to get the count of
     * @return count
     * @postcondition count >= 0
     */
    public int count(Object o);

	/**
	 * The total number of items in the hamper
	 * @return size
     * @postcondition size >= 0
	 */
	public int size();

	/**
	 * The sum of this hamper and the given hamper. If e occurs N times
	 * in this hamper and M times in the given hamper then it will occur N+M times
	 * in the resultant hamper.
	 * @param hamper
	 * @return result
	 * @postcondition for all e, result.count(e) = count(e) + hamper.count(e)
	 */
	public Hamper<E> sum(Hamper<? extends E> hamper);

	/**
	 * The iterator method. The iterator should yield a Count for each element
	 * that occurs at least once in the hamper.
	 */
	public Iterator<Count<E>> iterator();

	/**
	 * 
	 * @return price of hamper
	 */
	public int getPrice();
}
