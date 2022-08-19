package unsw.piazza;

import java.util.ArrayList;
import java.util.List;

/**
 * A thread in the Piazza forum.
 */
public class Thread {

    /**
     * Creates a new thread with a title and an initial first post.
     * The author of the first post at the time of thread creation is the owner of the thread.
     * The owner cannot change once the thread is created.
     * @param title
     * @param firstPost
     */
    public Thread(String title, Post firstPost) {}

    /**
     * @return The owner of the thread
     */
    public User getOwner() {
        return null;
    }

    /**
     * @return The title of the thread
     */
    public String getTitle() {
        return null;
    }

    /**
     * @return A SORTED list of unique tags
     */
    public List<String> getTags() {
        return null;
    }

    /**
     * @return A list of posts in this thread, in the order that they were published
     */
    public List<Post> getPosts() {
        return null;
    }

    /**
     * Adds the given post object into the list of posts in the thread.
     * @param post
     */
    public void publishPost(Post post) {}

    /**
     * Allows the given user to remove the Post from the thread.
     * Does nothing if the post is not in the thread.
     * @param post
     * @throws PermissionDeniedException if the given user is not an author of the post
     */
    public void removePost(Post post, User by) throws PermissionDeniedException {}

    /**
     * Allows the given uer to edit the thread title.
     * @param title
     * @param by
     * @throws PermissionDeniedException if the given user is not the owner of the thread.
     */
    public void setTitle(String title, User by) throws PermissionDeniedException {}

    /**
     * Allows the given user to replace the thread tags (list of strings)
     * @param tags
     * @param by
     * @throws PermissionDeniedException if the given user is not the owner of the thread.
     */
    public void setTags(String[] tags, User by) throws PermissionDeniedException {}
}
