package shopping;

import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.util.List;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.Arrays;

import unsw.shopping.Item;
import unsw.shopping.CheckoutSystem;

public class CheckoutSystemTest {

    private ByteArrayOutputStream out;

    @BeforeEach
    private void setup() {
        out = new ByteArrayOutputStream();
        System.setOut(new PrintStream(out));
    }

    @Test
    public void testColesCash() {
        List<Item> items = new ArrayList<Item>(
                Arrays.asList(new Item("Apple", 1), new Item("Orange", 1), new Item("Avocado", 5)));

        CheckoutSystem checkout = CheckoutSystem.instance("Coles");
        checkout.checkout(items, "cash", 200, true);

        String expected = "Welcome! Please scan your first item. If you have a flybuys card, please scan it at any time.\n"
                + "Paid $200 with $193 change.\n" + "Today at Coles you purchased the following:\n" + "- Apple : $1\n"
                + "- Orange : $1\n" + "- Avocado : $5\n";

        assertEquals(expected, out.toString().strip());
    }

    @Test
    public void testWooliesCash() {
        List<Item> items = new ArrayList<Item>(
                Arrays.asList(new Item("Apple", 1), new Item("Orange", 1), new Item("Avocado", 5)));

        CheckoutSystem checkout = CheckoutSystem.instance("Woolies");
        checkout.checkout(items, "cash", 200, true);

        String expected = "Welcome! Please scan your first item. If you have a Everyday Rewards card, please scan it at any time.\n"
                + "Paid $200 with $193 change.\n" + "Your purchase: Apple, ($1), Orange, ($1), Avocado ($5).\n";

        assertEquals(expected, out.toString().strip());
    }

    @Test
    public void testColesCard() {
        List<Item> items = new ArrayList<Item>(
                Arrays.asList(new Item("Apple", 1), new Item("Orange", 1), new Item("Avocado", 5)));

        CheckoutSystem checkout = CheckoutSystem.instance("Coles");
        checkout.checkout(items, "card", 200, true);

        String expected = "Welcome! Please scan your first item. If you have a flybuys card, please scan it at any time.\n"
                + "Paid $7.\n" + "Today at Coles you purchased the following:\n" + "- Apple : $1\n" + "- Orange : $1\n"
                + "- Avocado : $5\n";

        assertEquals(expected, out.toString().strip());
    }


    @Test
    public void testWooliesCard() {
        List<Item> items = new ArrayList<Item>(
                Arrays.asList(new Item("Apple", 1), new Item("Orange", 1), new Item("Avocado", 5)));

        CheckoutSystem checkout = CheckoutSystem.instance("Woolies");
        checkout.checkout(items, "card", 200, true);

        String expected = "Welcome! Please scan your first item. If you have a Everyday Rewards card, please scan it at any time.\n"
                + "Paid $7.\n" + "Your purchase: Apple, ($1), Orange, ($1), Avocado ($5).\n";

        assertEquals(expected, out.toString().strip());
    }

    @Test
    public void testColesNoReceipt() {
        List<Item> items = new ArrayList<Item>(
                Arrays.asList(new Item("Apple", 1), new Item("Orange", 1), new Item("Avocado", 5)));

        CheckoutSystem checkout = CheckoutSystem.instance("Coles");
        checkout.checkout(items, "card", 200, false);

        String expected = "Welcome! Please scan your first item. If you have a flybuys card, please scan it at any time.\n"
                + "Paid $7.\n";

        assertEquals(expected, out.toString().strip());
    }

    @Test
    public void testWooliesNoReceipt() {
        List<Item> items = new ArrayList<Item>(
                Arrays.asList(new Item("Apple", 1), new Item("Orange", 1), new Item("Avocado", 5)));

        CheckoutSystem checkout = CheckoutSystem.instance("Woolies");
        checkout.checkout(items, "card", 200, false);

        String expected = "Welcome! Please scan your first item. If you have a Everyday Rewards card, please scan it at any time.\n"
                + "Paid $7.\n";

        assertEquals(expected, out.toString().strip());
    }

    public static void assertEquals(String expected, String actual) {
        if (expected.replaceAll("\\s", "").equals(actual.replaceAll("\\s", ""))) {
            return;
        }

        String[] expectedLines = expected.split("[\n\r]");
        String[] actualLines = actual.split("[\n\r]");

        for (int i = 0; i < Math.min(expectedLines.length, actualLines.length); i++) {
            if (!expectedLines[i].replaceAll("\\s", "").equals(actualLines[i].replaceAll("\\s", ""))) {
                throw new RuntimeException("Expected output doesn't match actual outupt, issue is on line " + i + "\n"
                        + "Expected: " + expectedLines[i] + "\n" + "Actual: " + actualLines[i] + "\n"
                        + "(More issues may exist just breaking at first issue)");
            }
        }

        if (expectedLines.length != actualLines.length) {
            throw new RuntimeException("Expected doesn't match Actual\n==Expected==\n" + expected + "\n==Actual==\n" + actual);
        }
    }
}
