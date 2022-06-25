package blackout;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;

public class TestHelpers {
    public static void assertListAreEqualIgnoringOrder(List<?> a, List<?> b) {
        // containsAll both ways is important to handle dupes
        assertTrue(a.size() == b.size() && a.containsAll(b) && b.containsAll(a));
    }

    public static void assertListAreNotEqualIgnoringOrder(List<?> a, List<?> b) {
        // containsAll both ways is important to handle dupes
        assertFalse(a.size() == b.size() && a.containsAll(b) && b.containsAll(a));
    }
}
