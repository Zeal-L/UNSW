package q13.Composite;

import java.util.Map;

import org.json.JSONArray;
import org.json.JSONObject;

import q13.BusinessRule;
import q13.BusinessRuleException;
import q13.Component.CONSTANT;
import q13.Component.Component;

public class GREATERTHAN implements BusinessRule {
    private final Component comA;
    private final Component comB;

    public GREATERTHAN(Component comA, Component comB) {
        this.comA = comA;
        this.comB = comB;
    }
    
    public boolean evaluate(Map<String, Object> values) {
        Object v1 = comA.evaluate(values);
        Object v2 = comB.evaluate(values);


        if (!(v1 instanceof Number) || !(v2 instanceof Number)) {
            throw new BusinessRuleException("Both arguments must be numeric");
        }


        return (Integer)v1 > (Integer)v2;
    }

    public void updateBaseline(Integer factor) {
        if (comA instanceof CONSTANT) {
            ((CONSTANT) comA).updateBaseline(factor);
        }  
        if (comB instanceof CONSTANT) {
            ((CONSTANT) comB).updateBaseline(factor);
        } 
    }

    public JSONObject toJSON(Integer factor) {
        JSONObject json = new JSONObject();
        json.put("Operator", "GREATER THAN");
        JSONArray list = new JSONArray();
        list.put(comA.toJSON(factor));
        list.put(comB.toJSON(factor));
        json.put("Args", list);
        return json;
    }
}
    
