package bool;

public class ValueNode implements BooleanNode {
    private boolean value;

    public ValueNode(boolean value) {
        this.value = value;
    }
    
    public boolean evaluate() {
        return value;
    }
    public String prettyPrint() {
        return value ? "true" : "false";
    }
}
