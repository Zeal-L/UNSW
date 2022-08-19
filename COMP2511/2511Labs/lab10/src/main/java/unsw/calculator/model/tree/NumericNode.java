package unsw.calculator.model.tree;

import unsw.calculator.model.Visitor;

public class NumericNode implements TreeNode {

    private int value;

    public NumericNode(int val) {
        value = val;
    }
  
    public int getValue() {
        return value;
    }
  
    public String getLabel() {
       return String.valueOf(value);
    }

    @Override
    public void infixPrint() {
        System.out.print(getLabel());
    }
    
    @Override
    public void accept(Visitor visitor) {
        visitor.visitNumericNode(this);
    }
    
}