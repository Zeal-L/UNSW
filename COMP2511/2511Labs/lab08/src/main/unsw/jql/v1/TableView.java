package unsw.jql.v1;

import java.util.Iterator;

public interface TableView<E> extends Iterator<E>, Iterable<E>
{
    /**
     * Count number of records left
     */
    public int count();

    /**
     * Convert the remaining records into a table.
     */
    public Table<E> toTable();
}
