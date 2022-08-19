package unsw.calculator.model;

import unsw.calculator.model.tree.TreeNode;

/**
 * This class is just here to help you test things out with printing, etc.
 */
public class Main {
    public static void main(String[] args)  {
        Parser parser = new Parser("10 + 10 / 2 * 3 - 6"); // spaces are vital!!
        TreeNode node = parser.parse();
        node.infixPrint();
        System.out.println();
    }
}