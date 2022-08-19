package bool;

public class NotNode implements BooleanNode {
    private BooleanNode node;

    public NotNode(BooleanNode node) {
        this.node = node;
    }

    public boolean evaluate() {
        return !node.evaluate();
    }

    public String prettyPrint() {
        return "NOT(" + node.prettyPrint() + ")";
    }
}
