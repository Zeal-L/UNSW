package unsw.test;

import unsw.piazza.PiazzaForum;
import unsw.piazza.Post;
import unsw.piazza.Thread;
import unsw.piazza.User;
import unsw.piazza.PermissionDeniedException;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Arrays;
import java.util.List;

public class PiazzaTest {

    @Test
    public void testExampleUsage() {
        // Create a forum and make some posts!
        PiazzaForum forum = new PiazzaForum("COMP2511");
        assertEquals("COMP2511", forum.getName());

        User user1 = new User("Ian Jacobs");
        User user2 = new User("Scomo");
        User user3 = new User("Melanie Perkins");

        Thread funThread = forum.publish("The Real Question - Pineapple on Piazza", "Who likes pineapple on piazza?",
                user1);

        // this will verify that the setTags function throws an exception.
        // this is due to the fact that only user1 can set the tags since user1 created the thread.
        assertThrows(PermissionDeniedException.class, () -> {
            funThread.setTags(new String[] { "pineapple" }, user2);
        });

        assertDoesNotThrow(() -> {
            funThread.setTags(new String[] { "pizza", "coding", "social", "hobbies" }, user1);
        });
        assertTrue(
                Arrays.equals(new String[] { "coding", "hobbies", "pizza", "social" }, funThread.getTags().toArray()));

        funThread.publishPost(new Post("Yuck!", user2));
        funThread.publishPost(new Post("Yes, pineapple on pizza is the absolute best", user3));
        funThread.publishPost(new Post("I think you misspelled pizza btw", user3));

        // Update the title
        assertThrows(PermissionDeniedException.class, () -> {
            funThread.setTitle("Pineapple on Pizza", user3);
        });
        funThread.publishPost(new Post("I'll just fix that lol", user1));
        assertDoesNotThrow(() -> {
            funThread.setTitle("Pineapple on Pizza", user1);
        });

        // Change a user's name
        funThread.publishPost(new Post("Whoops, wrong prime minister!", user2));
        user2.setName("Malcom Turnbull");

        // Search by author
        List<Post> actualPosts = forum.searchByAuthor(user3);
        String expectedPosts[] = new String[] { "Yes, pineapple on pizza is the absolute best",
                "I think you misspelled pizza btw", };
        for (int i = 0; i < expectedPosts.length; i++) {
            assertEquals(actualPosts.get(i).getContent(), expectedPosts[i]);
        }

        // Upvote a post
        Post existing = funThread.getPosts().get(0);
        assertEquals("Who likes pineapple on piazza?", existing.getContent());

        existing.upvote(user1);
        existing.upvote(user2);
        existing.upvote(user3);

        assertEquals(existing.getUpvotes(), 3);

        // Set the content and check the author
        assertThrows(PermissionDeniedException.class, () -> {
            existing.setContent("empty", user2);
        });

        assertDoesNotThrow(() -> {
            existing.setContent("Who likes pineapple on pizza?", user1);
        });

        assertEquals("Who likes pineapple on pizza?", existing.getContent());
        assertEquals(existing.getAuthor().getName(), "Ian Jacobs");

        // Remove a post
        assertThrows(PermissionDeniedException.class, () -> {
            funThread.removePost(existing, user2);
        });

        assertDoesNotThrow(() -> {
            funThread.removePost(existing, user1);
        });

        assertEquals(5, funThread.getPosts().size());
    }

    @Test
    public void testSearchByTag() {
        PiazzaForum forum = new PiazzaForum("COMP2511");
        User user1 = new User("StudentA");
        User user2 = new User("StudentB");

        Thread labThread = forum.publish("Lab 01", "How do I do the piazza exercise?", user1);
        Thread assignmentThread = forum.publish("Assignment", "Are we back in blackout?", user2);

        assertDoesNotThrow(() -> {
            labThread.setTags(new String[] { "Java" }, user1);
        });
        assertDoesNotThrow(() -> {
            assignmentThread.setTags(new String[] { "Java" }, user2);
        });

        List<Thread> searchResults = forum.searchByTag("Java");
        assertEquals("Lab 01", searchResults.get(0).getTitle());
        assertEquals("Assignment", searchResults.get(1).getTitle());
    }
}
