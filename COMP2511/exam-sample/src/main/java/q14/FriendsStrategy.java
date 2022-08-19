package q14;

import java.util.Comparator;
import java.util.List;
import java.util.stream.Collectors;

public class FriendsStrategy<P extends Comparable<P>>
        implements SortingStrategy<P> {

    public List<Person<P>> sort(
            WasteBookController<P> controller,
            List<Person<P>> people) {
        Comparator<Person<P>> comparator = Comparator.comparing(p -> -controller.getFriends(p.getId()));
        comparator = comparator.thenComparing(Person::getId);

        return people.stream().sorted(comparator).collect(Collectors.toList());
    }
}
