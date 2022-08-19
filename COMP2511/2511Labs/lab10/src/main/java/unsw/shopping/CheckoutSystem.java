package unsw.shopping;

import java.util.List;
import java.util.ArrayList;
import java.util.Arrays;

public class CheckoutSystem {
    
    private String supermarket;
    private int amountPurchased;

    private CheckoutSystem(String supermarket) {
        this.supermarket = supermarket;
    }

    public static CheckoutSystem instance(String supermarket) {
        return new CheckoutSystem(supermarket);
    }

    public void checkout(List<Item> items, String paymentMethod, int paymentAmount, boolean receipt) {
        // Welcome the user
        String cardName = null;
        if (supermarket.equals("Coles")) {
            cardName = "flybuys";
        } else if (supermarket.equals("Woolies")) {
            cardName = "Everyday Rewards";
        }
        System.out.println("Welcome! Please scan your first item. If you have a " + cardName + " card, please scan it at any time.");


        // Scan the items
        scanItems(items);
        
        // Take the user's payment
        if (paymentAmount < amountPurchased) {
            System.out.println("Not enough $$$.");
            return;
        }

        if (paymentMethod.equals("cash")) {
            System.out.println("Paid $" + paymentAmount + " with $" + (paymentAmount - amountPurchased) + " change.");
        } else {
            paymentAmount = amountPurchased;
            System.out.println("Paid $" + paymentAmount + ".");
        }

        // Print the receipt
        if (receipt) {
            if (supermarket.equals("Woolies")) {
                System.out.print("Your purchase: ");
    
                for (int i = 0; i < items.size() - 1; i++) {
                    System.out.print(items.get(i).getName() + ", ($" + items.get(i).getPrice() + "), ");
                }
                System.out.println(items.get(items.size() - 1).getName() + " ($" + items.get(items.size() - 1).getPrice() + ").");
            } else if (supermarket.equals("Coles")) {
                System.out.println("Today at Coles you purchased the following:");
                
                for (Item item : items) {
                    System.out.println("- " + item.getName() + " : $" + item.getPrice());
                }
            } 
        }
    }

    public void scanItems(List<Item> items) {
        // Supermarkets have restrictions on the number of items allowed
        if (supermarket.equals("Coles")) {
            if (items.size() > 20) {
                System.out.println("Too many items.");
            }
        } else if (supermarket.equals("Woolies")) {
            if (items.size() >= 55) {
                System.out.println("Sorry, that's more than we can handle in a single order!");
            }
        }

        if (items.size() == 0) {
            System.out.println("You do not have any items to purchase.");
            return;
        }

        for (Item item : items) {
            amountPurchased += item.getPrice();
        }
    }

    public static void main(String[] args) {
        List<Item> items = new ArrayList<Item>(Arrays.asList(
            new Item("Apple", 1),
            new Item("Orange", 1),
            new Item("Avocado", 5)
        ));

        CheckoutSystem checkout = new CheckoutSystem("Woolies");
        checkout.checkout(items, "cash", 200, true);
    }

}