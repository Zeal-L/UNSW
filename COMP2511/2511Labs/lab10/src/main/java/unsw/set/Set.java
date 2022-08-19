package unsw.set;

/**
 * A generic finite set of elements. In operations where equality between
 * elements is decided the equals(...) method is used.
 *
 * @author Robert Clifton-Everest
 *
 * @param <E> The type of elements contained within this set.
 * @invariant All e in elements occur only once
 */
public interface Set<E> extends Iterable<E> {

    /**
     * Add an element to the set. Set is unchanged if it already contains the
     * element.
     *
     * @param e The element to add
     * @post contains(e)
     */
    public void add(E e);

    /**
     * Remove an element from the set.
     *
     * @param e The element to remove
     * @post !contains(e)
     */
    public void remove(E e);

    /**
     * Determine if the given element is in the set.
     *
     * @param e The element to test against
     * @return true - if the element is in the set, false otherwise
     */
    public boolean contains(Object e);

    /**
     * Get the number of elements in the set.
     * @return size - the number of elements in the set
     * @post size >= 0
     */
    public int size();

    /**
     * Determine if this set is a subset of another set.
     *
     * @param other The possible super set.
     * @return subset - Whether or not the subset relation holds.
     * @post subset if and only if (forall e. contains(e) => other.contains(e))
     */
    public boolean subsetOf(Set<?> other);

    /**
     * Return a new set that is the union of this set and the given set
     *
     * @param other The other set operand.
     * @return result - A new set that is the union of these two sets.
     * @post for all e in result, contains(e) or other.contains(e)
     */
    public Set<E> union(Set<? extends E> other);

    /**
     * Return a new set that is the intersection of this set and the given set
     *
     * @param other The other set operand.
     * @return result - A new set that is the intersection of these two sets.
     * @post for all e in result, contains(e) and other.contains(e)
     */
    public Set<E> intersection(Set<? extends E> other);

}

