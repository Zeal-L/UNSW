package unsw.calculator.model;

import java.util.Stack;

import unsw.calculator.model.tree.BinaryOperatorNode;
import unsw.calculator.model.tree.NumericNode;

public class EvaluatorVisitor implements Visitor { 
    private Stack<Integer> stack = new Stack<Integer>();
    
    public void visitBinaryOperatorNode(BinaryOperatorNode node) {
        node.getLeft().accept(this);
        node.getRight().accept(this);
        stack.push(node.compute(stack.remove(stack.size()-2), stack.pop()));
    }
    
    
    public void visitNumericNode(NumericNode node) {
        stack.push(node.getValue());
    }

    public int getValue() {
        return stack.pop();
    }
}