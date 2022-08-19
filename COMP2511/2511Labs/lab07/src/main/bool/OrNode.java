package bool;

public class OrNode implements BooleanNode {
    private BooleanNode left;
    private BooleanNode right;
    
    public OrNode(BooleanNode left, BooleanNode right) {
        this.left = left;
        this.right = right;
    }
    public boolean evaluate() {
        return left.evaluate() || right.evaluate();
    }

    
    public String prettyPrint() {
        return "(OR " + left.prettyPrint() + " " + right.prettyPrint() + ")";
    }
}
