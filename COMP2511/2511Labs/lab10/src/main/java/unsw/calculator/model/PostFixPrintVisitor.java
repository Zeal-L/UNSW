package unsw.calculator.model;

import unsw.calculator.model.tree.BinaryOperatorNode;
import unsw.calculator.model.tree.NumericNode;

public class PostFixPrintVisitor implements Visitor {


    public void visitBinaryOperatorNode(BinaryOperatorNode node) {
        node.getLeft().accept(this);
        System.out.print(" ");
        node.getRight().accept(this);
        System.out.print(" " + node.getLabel());
    }
    
    
    public void visitNumericNode(NumericNode node) {
        System.out.print(node.getValue());
    }
}