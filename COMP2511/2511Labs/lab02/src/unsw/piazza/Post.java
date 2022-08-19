package unsw.piazza;

/**
 * A post in the Piazza forum
 */
public class Post {

    /**
     * Creates a new post by the author with the given content.
     * @param content
     * @param author
     */
    public Post(String content, User author) {}

    /**
     * @return Author of the post
     */
    public User getAuthor() {
        return null;
    }

    /**
     * @return The content of the post
     */
    public String getContent() {
        return null;
    }

    /**
     * @return A non-negative integer representing the total number of upvotes
     */
    public int getUpvotes() {
        return 0;
    }

    /**
     *  Called when the given user wants to update the content
     *  @param content
     *  @throws PermissionDeniedException if the given user is not the author
     */
    public void setContent(String content, User by) throws PermissionDeniedException {}

    /**
     * Called when the given user wants to upvote this post.
     * A user can only perform an upvote once. If they try more than once, nothing happens.
     * Users can upvote their own posts.
     * @param by
     */
    public void upvote(User by) {}
}