package q14;

import java.util.List;

public interface SortingStrategy<P extends Comparable<P>> {
    public List<Person<P>> sort(
            WasteBookController<P> controller,
            List<Person<P>> people);
}
