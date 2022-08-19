package q13.Composite;

import java.util.Map;

import org.json.JSONObject;

import q13.BusinessRule;
import q13.Component.CONSTANT;
import q13.Component.Component;

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

    public JSONObject toJSON(Integer factor) {
        JSONObject json = new JSONObject();
        json.put("Operator", "NOT BLANK");
        json.put("Arg", component.toJSON(factor));
        return json;
    }
    
}
