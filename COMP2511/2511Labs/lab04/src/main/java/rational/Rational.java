package rational;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

public class Rational {
    private int greatestCommonDivisor(int a, int b) {
        a = Math.abs(a);
        b = Math.abs(b);
        if (a == b) return a;
        if (a > b) return greatestCommonDivisor(a - b, a);
        return greatestCommonDivisor(a, b - a);
    }

    private final List<String> SUPER_NUMS = new ArrayList<String>(Arrays.asList(new String[] {"⁰", "¹", "²", "³", "⁴", "⁵", "⁶", "⁷", "⁸", "⁹"}));

    private final List<String> SUB_NUMS = new ArrayList<String>(Arrays.asList(new String[] {"₀", "₁", "₂", "₃", "₄", "₅", "₆", "₇", "₈", "₉"}));

}