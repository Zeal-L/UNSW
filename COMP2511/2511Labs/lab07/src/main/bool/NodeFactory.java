package bool;

import org.json.JSONObject;

public class NodeFactory {

    public static BooleanNode createBooleanNode(JSONObject json) {
        BooleanNode node = null;
        String type = json.getString("node");
        switch (type) {
            case "and":
                node = new AndNode(createBooleanNode(json.getJSONObject("subnode1")), 
                                    createBooleanNode(json.getJSONObject("subnode2")));
                break;
            case "or":
                node = new OrNode(createBooleanNode(json.getJSONObject("subnode1")), 
                                    createBooleanNode(json.getJSONObject("subnode2")));
                break;
            case "not":
                node = new NotNode(createBooleanNode(json.getJSONObject("subnode")));
                break;
            case "value":
                node = new ValueNode(json.getBoolean("value"));
                break;
            default:
                System.out.println("Invalid node type: " + type);
                break;
        }

        return node;
    }
}