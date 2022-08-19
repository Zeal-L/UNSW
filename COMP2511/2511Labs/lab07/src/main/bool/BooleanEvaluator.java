package bool;

import java.io.FileReader;

import org.json.JSONObject;
import org.json.JSONTokener;

public class BooleanEvaluator {

    public static boolean evaluate(BooleanNode expression) {
        // Return the expression evaluated
        return expression.evaluate();
    }

    public static String prettyPrint(BooleanNode expression) {
        // Pretty print the expression
        return expression.prettyPrint();
    }

    public static void main(String[] args) {
    
        JSONObject info = null;
        try {
            info = new JSONObject(new JSONTokener(new FileReader("lab07/src/main/bool/example.json")));
        } catch (Exception e) {
            System.out.println(e.getMessage());
        }
        BooleanNode temp = NodeFactory.createBooleanNode(info);
        System.out.println(temp.prettyPrint());
        System.out.println(temp.evaluate());

        try {
            info = new JSONObject(new JSONTokener(new FileReader("lab07/src/main/bool/example2.json")));
        } catch (Exception e) {
            System.out.println(e.getMessage());
        }
        temp = NodeFactory.createBooleanNode(info);
        System.out.println(temp.prettyPrint());
        System.out.println(temp.evaluate());
    }

}