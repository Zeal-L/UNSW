package bool;

public class AndNode implements BooleanNode {
    private BooleanNode left;
    private BooleanNode right;
    
    public AndNode(BooleanNode left, BooleanNode right) {
        this.left = left;
        this.right = right;
    }
    
    public boolean evaluate() {
        return left.evaluate() && right.evaluate();
    }

    
    public String prettyPrint() {
        return "(AND " + left.prettyPrint() + " " + right.prettyPrint() + ")";
    }

}
    
