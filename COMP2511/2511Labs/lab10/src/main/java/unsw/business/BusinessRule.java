package unsw.business;

import java.util.Map;

public interface BusinessRule {
    public boolean evaluate(Map<String, Object> values);
}
