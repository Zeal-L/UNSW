package Structural.CompositePattern.main.Composite;

import java.util.Map;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import Structural.CompositePattern.main.BusinessRule;

public class AND implements BusinessRule {
    private final BusinessRule comA;
    private final BusinessRule comB;

    public AND(BusinessRule comA, BusinessRule comB) {
        this.comA = comA;
        this.comB = comB;
    }
    
    public boolean evaluate(Map<String, Object> values) {
        return comA.evaluate(values) && comB.evaluate(values);
    }

    public void updateBaseline(Integer factor) {
        comA.updateBaseline(factor);
        comB.updateBaseline(factor);
    }

    public JSONObject toJSON(Integer factor) throws JSONException {
        JSONObject json = new JSONObject();
        json.put("Operator", "AND");
        JSONArray list = new JSONArray();
        list.put(comA.toJSON(factor));
        list.put(comB.toJSON(factor));
        json.put("Args", list);
        return json;
    }
}

