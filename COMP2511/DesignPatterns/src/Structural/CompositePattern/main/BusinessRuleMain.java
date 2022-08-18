package Structural.CompositePattern.main;

import java.io.IOException;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import Structural.CompositePattern.main.Component.CONSTANT;
import Structural.CompositePattern.main.Component.Component;
import Structural.CompositePattern.main.Component.LOOKUP;
import Structural.CompositePattern.main.Composite.AND;
import Structural.CompositePattern.main.Composite.GREATERTHAN;
import Structural.CompositePattern.main.Composite.NOTBLANK;
import Structural.CompositePattern.main.Composite.OR;

public class BusinessRuleMain {

    /**
     * Loads a resource file given a certain path that is relative to resources/
     * for example `/dungeons/maze.json`. Will add a `/` prefix to path if it's not
     * specified.
     * 
     * @precondiction path exists as a file
     * @param path Relative to resources/ will add an implicit `/` prefix if not
     *             given.
     * @return The textual content of the given file.
     * @throws IOException If some other IO exception.
     */
    public static String loadResourceFile(String path) throws IOException {
        if (!path.startsWith("/")) {
            path = "/" + path;
        }
        String myResource = "/Users/Zeal/Desktop/COMP/COMP2511/DesignPatterns/src/Structural/CompositePattern/resources";
        return new String(java.nio.file.Files.readAllBytes(java.nio.file.Paths.get(myResource + path)));
    }

    public static BusinessRule generateRule(String inputBusinessRule) throws JSONException {
        return ruleFromJSON(new JSONObject(inputBusinessRule));
    }

    public static BusinessRule ruleFromJSON(JSONObject inputBusinessRule) throws JSONException {
        String operator = inputBusinessRule.getString("Operator");

        if (operator.equals("AND")) {
            JSONArray args = inputBusinessRule.getJSONArray("Args");
            return new AND(ruleFromJSON(args.getJSONObject(0)), ruleFromJSON(args.getJSONObject(1)));
        } else if (operator.equals("OR")) {
            JSONArray args = inputBusinessRule.getJSONArray("Args");
            return new OR(ruleFromJSON(args.getJSONObject(0)), ruleFromJSON(args.getJSONObject(1)));
        } else if (operator.equals("GREATER THAN")) {
            JSONArray args = inputBusinessRule.getJSONArray("Args");
            return new GREATERTHAN(ruleValueFromJSON(args.getJSONObject(0)), ruleValueFromJSON(args.getJSONObject(1)));
        } else if (operator.equals("NOT BLANK")) {
            JSONObject arg = inputBusinessRule.getJSONObject("Arg");
            return new NOTBLANK(ruleValueFromJSON(arg));
        }
        return null;
    }

    public static Component ruleValueFromJSON(JSONObject value) throws JSONException {
        String operator = value.getString("Operator");
        Object arg = value.get("Arg");
        if (operator.equals("LOOKUP")) {
            return new LOOKUP((String) arg);
        } else if (operator.equals("CONSTANT")) {
            return new CONSTANT((Integer) arg);
        }
        return null;
    }
}
