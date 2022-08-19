package sso;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;

import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import unsw.sso.ClientApp;
import unsw.sso.Browser;
import unsw.sso.providers.Hoogle;
import unsw.sso.providers.InstaHam;
import unsw.sso.providers.LinkedOut;

/**
 * SSO Tests
 * 
 * @author Braedon Wooding, Kaiqi Liang & Nick Patrikeos
 */
public class SSOTest {

    private final String password = "1234";

    @Nested
    public class RegressionTests {
        @Test
        public void regressionIntegrationTest() {
            // Create a provider
            Hoogle hoogle = new Hoogle();
            hoogle.addUser("user@hoogle.com.au", password);

            ClientApp app = new ClientApp("MyApp");
            // Allow users to login using hoogle
            app.registerProvider(hoogle);

            // Create a browser instance
            Browser browser = new Browser();

            // Visit our client application
            browser.visit(app);

            // Since the browser has no initial login credentials
            // it'll cause us to redirect to a page to select providers
            assertEquals("Select a Provider", browser.getCurrentPageName());

            // Since we are on the provider selection page we can 'interact' with the page
            // and through that select a provider. Interaction takes in a single `Object`
            browser.interact(hoogle);

            assertEquals("Hoogle Login", browser.getCurrentPageName());

            // since we are on the provider form
            // we can interact and provide a form submission
            browser.interact(hoogle.generateFormSubmission("user@hoogle.com.au", password));

            // This should inform the browser that the form is filled
            // Which will then authenticate the form with the third party provider
            // which causes the browser to redirect back to the login page with token
            // which causes the client application to validate the token
            // resulting in a redirect back to the home page.
            assertEquals("Home", browser.getCurrentPageName());
            assertTrue(app.hasUserForProvider("user@hoogle.com.au", hoogle));
        }

        @Test
        public void testIntegrationLoginWithHoogle() {
            ClientApp app = new ClientApp("MyApp");
            Browser browser = new Browser();
            Hoogle hoogle = new Hoogle();

            browser.visit(app);
            // no providers but it'll still show a select a provider screen
            assertEquals("Select a Provider", browser.getCurrentPageName());

            // hoogle is not registered so it shouldn't work
            browser.interact(hoogle);

            // Allow users to login using hoogle
            app.registerProvider(hoogle);

            // hoogle is now registered but it shouldn't allow any login
            browser.interact(hoogle);
            assertEquals("Hoogle Login", browser.getCurrentPageName());
            browser.interact(hoogle.generateFormSubmission("user@hoogle.com.au", password));
            // the above will generate null causing you to go back to the list of providers
            assertEquals("Select a Provider", browser.getCurrentPageName());

            // But if we add a user...
            hoogle.addUser("user@hoogle.com.au", password);

            browser.interact(hoogle);
            browser.interact(hoogle.generateFormSubmission("user@hoogle.com.au", password));
            // it should work!
            assertEquals("Home", browser.getCurrentPageName());
            assertTrue(app.hasUserForProvider("user@hoogle.com.au", hoogle));
        }

        @Test
        public void testLoginWithLinkedOut() {
            ClientApp app = new ClientApp("MyApp");
            Browser browser = new Browser();
            LinkedOut linkedOut = new LinkedOut();
            String email = "user@linkedout.com";

            app.registerProvider(linkedOut);

            // Visit application and select LinkedOut login provider
            browser.visit(app);
            browser.interact(linkedOut);
            assertEquals("LinkedOut Login", browser.getCurrentPageName());
            
            // Add a user
            linkedOut.addUser(email, password);
            // Login via LinkedOut, except with no password
            // This will still work as LinkedOut allows anonymous logins (login with empty password)
            browser.interact(linkedOut.generateFormSubmission(email, ""));
            assertEquals("Home", browser.getCurrentPageName());
            assertTrue(app.hasUserForProvider(email, linkedOut));
        }

        @Test
        public void testGoingBackAPage() {
            ClientApp app = new ClientApp("MyApp");
            Browser browser = new Browser();
            Hoogle hoogle = new Hoogle();
            hoogle.addUser("user@hoogle.com.au", password);
            app.registerProvider(hoogle);

            browser.visit(app);
            // no providers but it'll still show a select a provider screen
            assertEquals("Select a Provider", browser.getCurrentPageName());

            // null makes the browser backtrack
            browser.interact(null);
            assertEquals(browser.getCurrentPageName(), null);

            browser.visit(app);
            browser.interact(hoogle);
            assertEquals("Hoogle Login", browser.getCurrentPageName());
            browser.interact(null);
            assertEquals("Select a Provider", browser.getCurrentPageName());

            browser.interact(hoogle);
            assertEquals("Hoogle Login", browser.getCurrentPageName());
            browser.interact(hoogle.generateFormSubmission("badusername", password));
            assertEquals("Select a Provider", browser.getCurrentPageName());

            browser.interact(hoogle);
            assertEquals("Hoogle Login", browser.getCurrentPageName());
            browser.interact(hoogle.generateFormSubmission("user@hoogle.com.au", "bad password"));
            assertEquals("Select a Provider", browser.getCurrentPageName());

            // good login
            browser.interact(hoogle);
            browser.interact(hoogle.generateFormSubmission("user@hoogle.com.au", password));
            // it should work!
            assertEquals("Home", browser.getCurrentPageName());
            assertTrue(app.hasUserForProvider("user@hoogle.com.au", hoogle));

            browser.interact(null);
            // back to login
            assertEquals("Hoogle Login", browser.getCurrentPageName());
        }
    }

    @Nested
    public class Task2CacheTests {
        @Test
        public void testCache() {
            // Create a provider
            Hoogle hoogle = new Hoogle();
            hoogle.addUser("user@hoogle.com.au", password);
    
            ClientApp app = new ClientApp("MyApp");
            // Allow users to login using hoogle
            app.registerProvider(hoogle);
    
            // Create a browser instance
            Browser browser = new Browser();
            browser.visit(app);
    
            // The rest of the 6 steps are identical to the readme example
            assertEquals("Select a Provider", browser.getCurrentPageName());
            browser.interact(hoogle);
    
            assertEquals("Hoogle Login", browser.getCurrentPageName());
            browser.interact(hoogle.generateFormSubmission("user@hoogle.com.au", password));
    
            assertEquals("Home", browser.getCurrentPageName());
            assertTrue(app.hasUserForProvider("user@hoogle.com.au", hoogle));
    
            // now however if we redirect back to the same app we should stay on the home
            // page! Because of the cache
            browser.visit(app);
            assertEquals("Home", browser.getCurrentPageName());
            assertTrue(app.hasUserForProvider("user@hoogle.com.au", hoogle));
    
            // if it's a different instance though it shouldn't work
            ClientApp app2_butSame = new ClientApp("MyApp");
            browser.visit(app2_butSame);
            assertEquals("Select a Provider", browser.getCurrentPageName());
    
            browser.visit(app);
            assertEquals("Home", browser.getCurrentPageName());
            assertTrue(app.hasUserForProvider("user@hoogle.com.au", hoogle));
            browser.clearCache();
            // however, it should still stay on home here until we reload the page (/visit
            // it again)
            assertEquals("Home", browser.getCurrentPageName());
            assertTrue(app.hasUserForProvider("user@hoogle.com.au", hoogle));
            browser.visit(app);
            assertEquals("Select a Provider", browser.getCurrentPageName());
    
            // browsers don't share the cache
            Browser other = new Browser();
            other.visit(app);
            assertEquals("Select a Provider", other.getCurrentPageName());
    
            // an extension you could do here is if 2 applications share the same provider
            // they could share the same tokens... but not something we'll do in this lab
        }

        @Test
        public void testCacheGoingBack() {
            ClientApp app = new ClientApp("MyApp");
            Browser browser = new Browser();
            Hoogle hoogle = new Hoogle();
            hoogle.addUser("user@hoogle.com.au", password);
            app.registerProvider(hoogle);

            browser.visit(app);
            // no providers but it'll still show a select a provider screen
            assertEquals("Select a Provider", browser.getCurrentPageName());

            // good login
            browser.interact(hoogle);
            browser.interact(hoogle.generateFormSubmission("user@hoogle.com.au", password));
            // it should work!
            assertEquals("Home", browser.getCurrentPageName());
            assertTrue(app.hasUserForProvider("user@hoogle.com.au", hoogle));

            // reload to forget history
            browser.visit(app);
            assertEquals("Home", browser.getCurrentPageName());
            assertTrue(app.hasUserForProvider("user@hoogle.com.au", hoogle));

            // now if we try to go back it should go to null
            browser.interact(null);
            assertEquals(null, browser.getCurrentPageName());
        }
    }

    @Nested
    public class Task7LockingTests {
        @Test
        public void testSingleAndMultipleProviders() throws InterruptedException {
            ClientApp app = new ClientApp("MyApp");
            Browser browser = new Browser();
            String email = "user3@linkedoutANDhoogle.com.au";

            Hoogle hoogle = new Hoogle();
            hoogle.addUser(email, password);
            browser.visit(app);
            app.registerProvider(hoogle);

            // repeat 3 times
            for (int i = 0; i < 3; i++) {
                browser.interact(hoogle);
                assertEquals("Hoogle Login", browser.getCurrentPageName());
                browser.interact(hoogle.generateFormSubmission(email, "incorrect"));
                if (i < 2)
                    assertEquals("Select a Provider", browser.getCurrentPageName());
                else
                    assertEquals("Locked", browser.getCurrentPageName());
            }

            // note the user actually should still be registered
            assertTrue(app.hasUserForProvider(email, hoogle));

            // a locked user should be able to go back to select a provider
            browser.interact(null);
            assertEquals("Select a Provider", browser.getCurrentPageName());

            // but using that provider again should lock it again
            browser.interact(hoogle);
            assertEquals("Hoogle Login", browser.getCurrentPageName());
            browser.interact(hoogle.generateFormSubmission(email, "incorrect"));
            assertEquals("Locked", browser.getCurrentPageName());

            // using a different provider though... should still result in a lock
            LinkedOut linkedOut = new LinkedOut();
            linkedOut.addUser(email, password);
            app.registerProvider(linkedOut);

            browser.interact(null);
            assertEquals("Select a Provider", browser.getCurrentPageName());
            browser.interact(linkedOut);
            assertEquals("LinkedOut Login", browser.getCurrentPageName());

            browser.interact(linkedOut.generateFormSubmission(email, password));
            assertEquals("Locked", browser.getCurrentPageName());
            assertTrue(app.hasUserForProvider(email, linkedOut));
            assertTrue(app.hasUserForProvider(email, hoogle));

            // a different email should be fine though
            String differentEmail = "user2@hoogle.com.au";
            hoogle.addUser(differentEmail, password);
            browser.clearCache();
            browser.visit(app);
            browser.interact(hoogle);
            assertEquals("Hoogle Login", browser.getCurrentPageName());
            browser.interact(hoogle.generateFormSubmission(differentEmail, password));
            assertEquals("Home", browser.getCurrentPageName());

            // even if we fail login twice we should still be able to login
            browser.clearCache();
            browser.visit(app);

            // repeat 2 times
            for (int i = 0; i < 2; i++) {
                browser.interact(hoogle);
                assertEquals("Hoogle Login", browser.getCurrentPageName());
                browser.interact(hoogle.generateFormSubmission("user2@hoogle.com.au", "12349"));
                assertEquals("Select a Provider", browser.getCurrentPageName());
            }

            browser.interact(hoogle);
            assertEquals("Hoogle Login", browser.getCurrentPageName());
            browser.interact(hoogle.generateFormSubmission("user2@hoogle.com.au", password));
            assertEquals("Home", browser.getCurrentPageName());
        }

        @Test
        public void testLockingComplexNoCache() throws InterruptedException {
            ClientApp app = new ClientApp("MyApp1");
            ClientApp app2 = new ClientApp("MyApp2");
            Browser browser = new Browser();
            String email = "user5@linkedoutANDhoogle.com.au";

            Hoogle hoogle = new Hoogle();
            hoogle.addUser(email, password);

            LinkedOut linkedOut = new LinkedOut();
            linkedOut.addUser(email, password);

            browser.visit(app);
            app.registerProvider(hoogle);
            app2.registerProvider(linkedOut);

            // repeat 3 times to lock
            for (int i = 0; i < 3; i++) {
                browser.interact(hoogle);
                assertEquals("Hoogle Login", browser.getCurrentPageName());
                browser.interact(hoogle.generateFormSubmission(email, "incorrect"));
                if (i < 2)
                    assertEquals("Select a Provider", browser.getCurrentPageName());
                else
                    assertEquals("Locked", browser.getCurrentPageName());
            }

            // note the user actually should be registered (but locked)
            assertTrue(app.hasUserForProvider(email, hoogle));

            // we can however login to the other website using the same email if it's
            // a different provider since the provider isn't registered on that website
            browser.visit(app2);
            browser.interact(linkedOut);
            assertEquals("LinkedOut Login", browser.getCurrentPageName());
            browser.interact(linkedOut.generateFormSubmission(email, password));

            assertEquals("Home", browser.getCurrentPageName());
            assertTrue(app2.hasUserForProvider(email, linkedOut));
            assertFalse(app2.hasUserForProvider(email, hoogle));

            app2.registerProvider(hoogle);
            // clear cache to make it simpler
            browser.clearCache();
            browser.visit(app2);
            browser.interact(linkedOut);
            assertEquals("LinkedOut Login", browser.getCurrentPageName());
            browser.interact(linkedOut.generateFormSubmission(email, password));
            assertEquals("Locked", browser.getCurrentPageName());

            // the user for the locked provider should be auto created as well
            assertTrue(app2.hasUserForProvider(email, linkedOut));
            assertTrue(app2.hasUserForProvider(email, hoogle));
        }

        @Test
        public void testLockingComplexWithCache() throws InterruptedException {
            ClientApp app = new ClientApp("MyApp1");
            ClientApp app2 = new ClientApp("MyApp2");
            Browser browser = new Browser();
            String email = "user5@linkedoutANDhoogle.com.au";

            Hoogle hoogle = new Hoogle();
            hoogle.addUser(email, password);

            LinkedOut linkedOut = new LinkedOut();
            linkedOut.addUser(email, password);

            browser.visit(app);
            app.registerProvider(hoogle);
            app2.registerProvider(linkedOut);

            // repeat 3 times to lock
            for (int i = 0; i < 3; i++) {
                browser.interact(hoogle);
                assertEquals("Hoogle Login", browser.getCurrentPageName());
                browser.interact(hoogle.generateFormSubmission(email, "incorrect"));
                if (i < 2)
                    assertEquals("Select a Provider", browser.getCurrentPageName());
                else
                    assertEquals("Locked", browser.getCurrentPageName());
            }

            // note the user actually should be registered (but locked)
            assertTrue(app.hasUserForProvider(email, hoogle));

            // we can however login to the other website using the same email if it's
            // a different provider since the provider isn't registered on that website
            browser.visit(app2);
            browser.interact(linkedOut);
            assertEquals("LinkedOut Login", browser.getCurrentPageName());
            browser.interact(linkedOut.generateFormSubmission(email, password));

            assertEquals("Home", browser.getCurrentPageName());
            assertTrue(app2.hasUserForProvider(email, linkedOut));
            assertFalse(app2.hasUserForProvider(email, hoogle));

            // if we then register hoogle it should prevent even a cache visit
            app2.registerProvider(hoogle);
            browser.visit(app2);
            assertEquals("Locked", browser.getCurrentPageName());
            assertTrue(app2.hasUserForProvider(email, linkedOut));
            assertTrue(app2.hasUserForProvider(email, hoogle));
        }
    }

    @Nested
    public class Task8InstaHamTests {
        @Test
        public void testInstaHamBasic() throws IOException, InterruptedException {
            ClientApp app = new ClientApp("MyApp");
            Browser browser = new Browser();
            InstaHam instaham = new InstaHam();
            String email = "user@ham.com.au";

            instaham.addUser(email, browser);

            Hoogle hoogle = new Hoogle();
            hoogle.addUser("user@hoogle.com.au", password);

            // register ham but not hoogle
            app.registerProvider(instaham);

            browser.visit(app);
            assertEquals("Select a Provider", browser.getCurrentPageName());

            // we shouldn't be able to visit hoogle
            browser.interact(hoogle);
            assertEquals("Select a Provider", browser.getCurrentPageName());

            // but ham should work
            browser.interact(instaham);
            assertEquals("InstaHam Login", browser.getCurrentPageName());

            // valid user
            browser.interact(email);
            Thread.sleep(800);

            // we should get an 'email'
            // and thus the browser should automatically log us in, however this isn't
            // instant
            // so we'll wait a second or two before triggering the check
            assertEquals("Home", browser.getCurrentPageName());
            assertTrue(app.hasUserForProvider(email, instaham));

            // the cache should still work
            browser.visit(app);
            assertEquals("Home", browser.getCurrentPageName());
            assertTrue(app.hasUserForProvider(email, instaham));
        }

        @Test
        public void testInstaHamMultipleUsers() throws InterruptedException {
            ClientApp app = new ClientApp("MyApp");
            Browser browser = new Browser();
            InstaHam instaham = new InstaHam();
            String firstUser = "user2@ham.com.au";
            String secondUser = "user3@ham.com.au";
            instaham.addUser(firstUser, browser);

            Hoogle hoogle = new Hoogle();
            hoogle.addUser("user@hoogle.com.au", password);
            browser.visit(app);

            // register ham but not hoogle
            app.registerProvider(instaham);

            // if we have a different user it should choose the correct one
            instaham.addUser(secondUser, browser);
            browser.interact(instaham);
            assertEquals("InstaHam Login", browser.getCurrentPageName());

            browser.interact(firstUser);
            Thread.sleep(800);
            assertEquals("Home", browser.getCurrentPageName());
            assertTrue(app.hasUserForProvider(firstUser, instaham));

            browser.interact(null);

            browser.interact(secondUser);
            Thread.sleep(800);
            assertEquals("Home", browser.getCurrentPageName());
            assertTrue(app.hasUserForProvider(secondUser, instaham));
        }

        @Test
        public void testInstaHamMultipleProviders() throws InterruptedException {
            ClientApp app = new ClientApp("MyApp");
            Browser browser = new Browser();
            InstaHam instaham = new InstaHam();
            String email = "user@hamANDhoogle.com.au";
            instaham.addUser(email, browser);

            Hoogle hoogle = new Hoogle();
            hoogle.addUser(email, password);
            browser.visit(app);

            // register ham AND hoogle
            app.registerProvider(instaham);
            app.registerProvider(hoogle);

            browser.interact(instaham);
            assertEquals("InstaHam Login", browser.getCurrentPageName());

            browser.interact(email);
            Thread.sleep(800);
            assertEquals("Home", browser.getCurrentPageName());
            assertTrue(app.hasUserForProvider(email, instaham));
            assertFalse(app.hasUserForProvider(email, hoogle));

            browser.interact(null);
            assertEquals("InstaHam Login", browser.getCurrentPageName());
            browser.interact(null);
            assertEquals("Select a Provider", browser.getCurrentPageName());
            browser.interact(hoogle);

            browser.interact(hoogle.generateFormSubmission(email, password));
            assertEquals(browser.getCurrentPageName(), "Home");
            assertTrue(app.hasUserForProvider(email, instaham));
            assertTrue(app.hasUserForProvider(email, hoogle));
        }

        @Test
        public void testUsingIncorrectProviderOnWrongLogin() throws InterruptedException {
            ClientApp app = new ClientApp("MyApp");
            Browser browser = new Browser();
            InstaHam instaham = new InstaHam();
            String email = "user2@hamANDhoogle.com.au";
            instaham.addUser(email, browser);

            Hoogle hoogle = new Hoogle();
            hoogle.addUser(email, password);
            browser.visit(app);

            // register ham AND hoogle
            app.registerProvider(instaham);
            app.registerProvider(hoogle);

            browser.interact(hoogle);
            assertEquals("Hoogle Login", browser.getCurrentPageName());

            browser.interact(email);
            Thread.sleep(800);
            assertEquals("Select a Provider", browser.getCurrentPageName());

            browser.interact(instaham);
            browser.interact(hoogle.generateFormSubmission(email, password));
            assertEquals("Home", browser.getCurrentPageName());
        }
    }
}
