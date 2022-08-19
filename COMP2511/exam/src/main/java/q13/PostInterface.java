package q13;

public interface PostInterface {
    public abstract String addPost(Post post);
    public abstract void updatePost(String postID, String newContent);
    public abstract void deletePost(String postID);
    
}
