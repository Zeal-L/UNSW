package q13.Component;

import java.util.Map;

import org.json.JSONObject;

public class LOOKUP implements Component {

    protected final String Value;

    public LOOKUP(String Value) {
        this.Value = Value;
    }
    
    public Object evaluate(Map<String, Object> values) {
        return values.get(Value);
    }

    public JSONObject toJSON(Integer factor) {
        JSONObject json = new JSONObject();
        json.put("Operator", "LOOKUP");
        json.put("Arg", Value);
        return json;
    }
    
}
