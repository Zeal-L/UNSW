package q13;

import java.io.IOException;

import org.json.JSONArray;
import org.json.JSONObject;

import q13.Component.CONSTANT;
import q13.Component.Component;
import q13.Component.LOOKUP;
import q13.Composite.AND;
import q13.Composite.GREATERTHAN;
import q13.Composite.NOTBLANK;
import q13.Composite.OR;

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
        if (!path.startsWith("/"))
            path = "/" + path;
        return new String(BusinessRuleMain.class.getResourceAsStream(path).readAllBytes());
    }

    public static BusinessRule generateRule(String inputBusinessRule) {
        return ruleFromJSON(new JSONObject(inputBusinessRule));
    }

    public static BusinessRule ruleFromJSON(JSONObject inputBusinessRule) {
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


    public static Component ruleValueFromJSON(JSONObject value) {
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
