package q14.gitlab;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;

import org.json.JSONArray;
import org.json.JSONObject;
import org.junit.jupiter.api.Nested;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;

import org.skyscreamer.jsonassert.JSONAssert;
import org.junit.jupiter.api.Test;

public class GitlabTest {
    private static JSONObject jsonExpected() {
        JSONObject blackout = new JSONObject();
        blackout.put("type", "project");
        blackout.put("name", "blackout");

        JSONObject dungeonmania = new JSONObject();
        dungeonmania.put("type", "project");
        dungeonmania.put("name", "dungeonmania");

        JSONObject expectedSubgroup = new JSONObject();
        expectedSubgroup.put("name", "22T2");
        expectedSubgroup.put("type", "group");
        expectedSubgroup.put("subgroups", new JSONArray(new JSONObject[]{dungeonmania}));

        JSONObject expected = new JSONObject();
        expected.put("name", "COMP2511");
        expected.put("type", "group");
        expected.put("subgroups", new JSONArray(new JSONObject[]{expectedSubgroup, blackout}));
        
        return expected;
    }

    @Nested
    public class RegressionTests {
        @Test
        public void testIntegration() {
            User user = new User("Claire");
            User user2 = new User("Eddie");

            GitlabPermissionsNode group = new GitlabGroup("COMP2511", user);
            assertEquals(PermissionsLevel.OWNER, group.getUserPermissions(user));
            GitlabPermissionsNode group2 = assertDoesNotThrow(() -> group.createSubgroup("22T2", user));

            assertEquals("22T2", group2.getName());
            assertEquals(PermissionsLevel.OWNER, group2.getUserPermissions(user));
            
            assertDoesNotThrow(() -> group2.updateUserPermissions(user2, PermissionsLevel.MAINTAINER, user));
            assertEquals(PermissionsLevel.MAINTAINER, group2.getUserPermissions(user2));

            assertThrows(GitlabAuthorisationException.class, () -> group2.updateUserPermissions(user, PermissionsLevel.NONE, user2));
        }

        @Test
        public void testToJSON() {
            User user = new User("Claire");
            GitlabPermissionsNode group = new GitlabGroup("COMP2511", user);
            GitlabPermissionsNode group2 = assertDoesNotThrow(() -> group.createSubgroup("22T2", user));
            assertDoesNotThrow(() -> group.createProject("blackout", user));
            assertDoesNotThrow(() -> group2.createProject("dungeonmania", user));

            JSONAssert.assertEquals(jsonExpected(), group.toJSON(), true);
        }
    }

    @Nested
    public class PartDFilteringAuthorisationTests {
        @Test
        public void testFiltering() {
            User user = new User("Claire");
            User user2 = new User("Eddie");

            GitlabPermissionsNode group = new GitlabGroup("COMP2511", user);
            assertEquals(PermissionsLevel.OWNER, group.getUserPermissions(user));
            GitlabPermissionsNode group2 = assertDoesNotThrow(() -> group.createSubgroup("22T2", user));
            assertDoesNotThrow(() -> group.updateUserPermissions(user2, PermissionsLevel.DEVELOPER, user));
            assertEquals(PermissionsLevel.DEVELOPER, group2.getUserPermissions(user2));
            
            assertThrows(GitlabAuthorisationException.class, () -> group2.updateUserPermissions(user2, PermissionsLevel.REPORTER, user));
        }
    }
    
    @Nested
    public class PartEFactoryTests {
        @Test
        public void testFactory() throws IOException {
            User user = new User("Claire");
            String input = GitlabFactory.loadResourceFile("example.json");

            GitlabPermissionsNode group = GitlabFactory.gitlabFromJson(input, user);
            assertEquals(PermissionsLevel.OWNER, group.getUserPermissions(user));
            JSONAssert.assertEquals(jsonExpected(), group.toJSON(), true);
        }
    }

    @Nested
    public class PartFSingletonTests {
        private int ref = 0;

        @Test
        public void testSingleton() throws InterruptedException {
            User user = new User("Claire");
            GitlabProject project = new GitlabProject("exam", user);


            Runnable job = () -> {
                try {
                    ref += 1;
                    Thread.sleep(2000);
                } catch (InterruptedException e) {}
            };

            Thread t1 = new Thread(() -> project.runPipeline(job)); 
            t1.start(); 
            assertTrue(ref < 2); // run once, ref should be incremented to 1, then sleep for 2 seconds
            Thread t2 = new Thread(() -> project.runPipeline(job)); 
            t2.start();
            assertTrue(ref < 2); // ref is still 0 or 1, since second job is queued
            Thread t3 = new Thread(() -> project.runPipeline(job)); 
            t3.start();
            assertTrue(ref < 2); // ref is still 0 or 1, since third job is queued
            Thread.sleep(1000);
            assertEquals(ref, 1); // ref is now 1, first job still running
            Thread.sleep(2000);
            assertEquals(2, ref); // ref is now 2, second job is running and third is queued
            Thread.sleep(2000);
            assertEquals(3, ref); // ref is now 3, third job has run

            ref = 0; // reset ref
        }
    }
}