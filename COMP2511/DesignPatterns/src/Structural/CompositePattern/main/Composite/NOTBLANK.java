package Structural.CompositePattern.main.Composite;

import java.util.Map;

import org.json.JSONException;
import org.json.JSONObject;

import Structural.CompositePattern.main.BusinessRule;
import Structural.CompositePattern.main.Component.CONSTANT;
import Structural.CompositePattern.main.Component.Component;

public class NOTBLANK implements BusinessRule {
    private final Component component;
    
    public NOTBLANK(Component component) {
        this.component = component;
    }
    
    public boolean evaluate(Map<String, Object> values) {
        Object val = component.evaluate(values);

        if (val == null) {
            return false;
        }

        return !((String) val).isBlank();
    }

    public void updateBaseline(Integer factor) {
        if (component instanceof CONSTANT) {
            ((CONSTANT) component).updateBaseline(factor);
        }   
    }

    public JSONObject toJSON(Integer factor) throws JSONException {
        JSONObject json = new JSONObject();
        json.put("Operator", "NOT BLANK");
        json.put("Arg", component.toJSON(factor));
        return json;
    }
    
}
