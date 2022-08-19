package degree;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;
import org.skyscreamer.jsonassert.JSONAssert;
import org.json.JSONObject;
import java.nio.file.Files;
import java.nio.file.Paths;

import java.io.IOException;

/**
 * A near-complete suite of tests for the Degree Distribution problem
 * @author Nick Patrikeos
 */
public class DegreeTest {

    public static JSONObject parseJSON(String filename) {
        try {
            String content = new String(Files.readAllBytes(Paths.get(filename)));
            return new JSONObject(content);
        } catch (IOException e) {
            return null;
        }
    }

    public static void testHelper(String expectedFilename, String degreeFilename, String studentsFilename) {
        // Because of the way JUnit is configured (run in a random temp folder on your
        // machine instead of just locally),
        // all our test data files need to be prefixed with bin/degree/data
        // and then the filename in use.
        // If you want to create your own test data,
        // Create the files locally and then reset the java workspace so they get put
        // into the temp folder.

        DegreeDistribution d = new DegreeDistribution();
        JSONObject actual = d.distribute("bin/degree/data/" + degreeFilename, "bin/degree/data/" + studentsFilename);
        JSONObject expected = parseJSON("bin/degree/data/" + expectedFilename);
        JSONAssert.assertEquals(expected, actual, true);
    }

    @Test
    public void testDocumentation() {
        testHelper("expectedDocumentation.json", "degreesDocumentation.json", "studentsDocumentation.json");
    }

    @Test
    public void testSingleDegreeSingleStudent() {
        testHelper("expectedSingle.json", "degreesSingle.json", "studentsSingle.json");
    }

    @Test
    public void testNoEvictions() {
        testHelper("expectedNoEvictions.json", "degreesNoEvictions.json", "studentsNoEvictions.json");
    }

    @Test
    public void testBonusMarksNoEvictions() {
        testHelper("expectedBonusNoEvictions.json", "degreesBonusNoEvictions.json", "studentsBonusNoEvictions.json");
    }

    @Test
    public void testEviction() {
        testHelper("expectedEvictions.json", "degreesEvictions.json", "studentsEvictions.json");
    }
}