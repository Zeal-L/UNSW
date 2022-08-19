package unsw.calculator.model;

import unsw.calculator.model.tree.BinaryOperatorNode;
import unsw.calculator.model.tree.NumericNode;

public class InFixPrintVisitor implements Visitor {
    public void visitBinaryOperatorNode(BinaryOperatorNode node) {
        node.infixPrint();
    }
    
    
    public void visitNumericNode(NumericNode node) {
        node.infixPrint();
    }

}