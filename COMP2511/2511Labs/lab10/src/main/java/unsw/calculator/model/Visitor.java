package unsw.calculator.model;

import unsw.calculator.model.tree.BinaryOperatorNode;
import unsw.calculator.model.tree.NumericNode;

/*
 * Abstract superclass of all visitors
 */
public interface Visitor {

    /**
     * Visits a composite node in the expression tree.
     * @param node
     */
    public abstract void visitBinaryOperatorNode(BinaryOperatorNode node);
    
    /**
     * Visits a compound node in the expression tree.
     * @param node
     */
    public abstract void visitNumericNode(NumericNode node);

}