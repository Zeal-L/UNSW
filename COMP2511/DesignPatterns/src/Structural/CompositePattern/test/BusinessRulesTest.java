package Structural.CompositePattern.test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;


import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

import org.json.JSONException;
import org.json.JSONObject;
import org.junit.Test;

import Structural.CompositePattern.main.BusinessRule;
import Structural.CompositePattern.main.BusinessRuleMain;

public class BusinessRulesTest {
    // This test may seem small but actually ends up having pretty high coverage, you don't have to write much more code to handle the other cases
    @Test
    public void testIntegration() throws IOException, JSONException {
        BusinessRule hasResponsesAndEitherPhoneNumberOrEmail = BusinessRuleMain.generateRule(BusinessRuleMain.loadResourceFile("example2.json"));

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

    @Test
    public void testUpdateBaseline() throws IOException, JSONException {
        BusinessRule hasResponsesAndEitherPhoneNumberOrEmail = BusinessRuleMain.generateRule(BusinessRuleMain.loadResourceFile("example2.json"));
        Map<String, Object> personA = new HashMap<>();
        personA.put("responses", 10);
        personA.put("invites", 10);
        hasResponsesAndEitherPhoneNumberOrEmail.updateBaseline(2);
        assertFalse(hasResponsesAndEitherPhoneNumberOrEmail.evaluate(personA));

    }

    @Test
    public void testToJson() throws IOException, JSONException {
        String expected = BusinessRuleMain.loadResourceFile("example2.json");
        BusinessRule hasResponsesAndEitherPhoneNumberOrEmail = BusinessRuleMain.generateRule(expected);
        
        JSONObject json = hasResponsesAndEitherPhoneNumberOrEmail.toJSON(1);
        
        assertEquals(expected.replaceAll("\\s", ""), json.toString().replaceAll("\\s", ""));

    }

    @Test
    public void testToJson2() throws IOException, JSONException {
        String expected = BusinessRuleMain.loadResourceFile("example2.json");
        BusinessRule hasResponsesAndEitherPhoneNumberOrEmail = BusinessRuleMain.generateRule(expected);
        
        JSONObject json = hasResponsesAndEitherPhoneNumberOrEmail.toJSON(2);
        
        assertEquals(expected.replaceAll("\\s", "").replace('2', '4'), json.toString().replaceAll("\\s", ""));
    }

}
