package Structural.CompositePattern.main.Composite;

import java.util.Map;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import Structural.CompositePattern.main.BusinessRule;
import Structural.CompositePattern.main.BusinessRuleException;
import Structural.CompositePattern.main.Component.CONSTANT;
import Structural.CompositePattern.main.Component.Component;

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

    public JSONObject toJSON(Integer factor) throws JSONException {
        JSONObject json = new JSONObject();
        json.put("Operator", "GREATER THAN");
        JSONArray list = new JSONArray();
        list.put(comA.toJSON(factor));
        list.put(comB.toJSON(factor));
        json.put("Args", list);
        return json;
    }
}
    
