package q13.Component;

import java.util.Map;

import org.json.JSONObject;

public interface Component {
    
    public abstract Object evaluate(Map<String, Object> values);
    public abstract JSONObject toJSON(Integer factor);
}


