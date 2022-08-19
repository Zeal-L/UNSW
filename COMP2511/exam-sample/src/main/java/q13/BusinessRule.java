package q13;

import java.util.Map;

import org.json.JSONObject;

public interface BusinessRule {
    public abstract boolean evaluate(Map<String, Object> values);
    public abstract void updateBaseline(Integer factor);
    public abstract JSONObject toJSON(Integer factor);
}
