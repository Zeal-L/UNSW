package unsw.calculator.model;

import java.util.StringTokenizer;

import unsw.calculator.model.tree.NumericNode;
import unsw.calculator.model.tree.TreeNode;
import unsw.calculator.model.tree.compound.AdditionNode;
import unsw.calculator.model.tree.compound.SubtractionNode;
import unsw.calculator.model.tree.compound.MultiplicationNode;
import unsw.calculator.model.tree.compound.DivisionNode;

/*
 * This class parses the given expression into a parse tree
 */
public class Parser {

    private StringTokenizer lexAnalyser;
    private String[] operators = new String[]{"+", "-", "*", "/"};
    private String lexItem;

    public Parser(String expression) {
        lexAnalyser = new StringTokenizer(expression);
    }

    public TreeNode parse() {
        getNextToken();
        return this.parseExpression(0);
    }

    private TreeNode parseExpression(int priority)  {
        TreeNode lhs = parseInteger();
        if (lhs == null) return null;

        while (isOperator(lexItem) && priority <= leftPrecedence(lexItem))  {
            String op = lexItem;
            getNextToken();
            TreeNode rhs = parseExpression(rightPrecedence(op));

            if (rhs == null) {
                System.out.println("Error in expression");
                System.exit(1);
            } else {
                TreeNode temp = lhs;
                switch (op) {
                    case "+": lhs = new AdditionNode(temp, rhs); break;
                    case "-": lhs = new SubtractionNode(temp, rhs); break;
                    case "*": lhs = new MultiplicationNode(temp, rhs); break;
                    case "/": lhs = new DivisionNode(temp, rhs); break;
                }
            }
        }
        
        return lhs;
    }

    private TreeNode parseInteger() {
        TreeNode nodep = null;

        if (this.isInteger(lexItem))  {
            nodep = new NumericNode(Integer.parseInt(lexItem));
            if (this.lexAnalyser.hasMoreTokens())
            getNextToken();
            else
            this.lexItem = null;
        }
        else  {
            System.out.println("Error in expression " + lexItem);
            System.exit(1);
        }
        return nodep;
    }

    private int leftPrecedence(String op) {
        if (op.equals("*"))
            return 3;
        else if (op.equals("/"))
            return 3;
        else if (op.equals("+"))
            return 1;
        else if (op.equals("-"))
            return 1;
        else
            return - 1;
    }

    private int rightPrecedence(String op)  {
        if (op.equals("*"))
            return 4;
        else if (op.equals("/"))
            return 4;
        else if (op.equals("+"))
            return 2;
        else if (op.equals("-"))
            return 2;
        else
            return - 1;
    }

    private boolean isInteger(String integer) {
        try {
            Integer.parseInt(integer);
            return true;
        }
        catch (NumberFormatException nfe) {
            return false;
        }
    }

    private boolean isOperator(String op) {
        boolean isOp = false;
        for (int i = 0; i < operators.length; i++)
            if (operators[i].equals(op))
            isOp = true;
        return isOp;
    }

    private void getNextToken() {
        lexItem = lexAnalyser.nextToken();
    }
}
