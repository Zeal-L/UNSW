package business;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HashMap;
import java.util.Map;

import org.junit.jupiter.api.Test;

import unsw.business.BusinessRule;
import unsw.business.BusinessRuleMain;

public class BusinessRulesTest {
    // This test may seem small but actually ends up having pretty high coverage, you don't have to write much more code to handle the other cases
    @Test
    public void testIntegration() throws IOException {
        BusinessRule hasResponsesAndEitherPhoneNumberOrEmail = BusinessRuleMain.generateRule(BusinessRuleMain.loadResourceFile("examples/example2.json"));

        // personA has responses > invites / 2 but doesn't have either a PhoneNumber or an Email
        Map<String, Object> personA = new HashMap<>();
        personA.put("responses", 10);
        personA.put("invites", 10);

        assertFalse(hasResponsesAndEitherPhoneNumberOrEmail.evaluate(personA));

        // personB has a phone number but has not enough responses
        Map<String, Object> personB = new HashMap<>();
        personB.put("responses", 0);
        personB.put("invites", 5);
        personB.put("phoneNumber", "0482839292");

        assertFalse(hasResponsesAndEitherPhoneNumberOrEmail.evaluate(personB));

        // this user has enough responses, and a valid email
        Map<String, Object> personC = new HashMap<>();
        personC.put("responses", 105019);
        personC.put("invites", 105020);
        personC.put("email", "cs2511@cse.unsw.edu.au");

        assertTrue(hasResponsesAndEitherPhoneNumberOrEmail.evaluate(personC));
    }
}
