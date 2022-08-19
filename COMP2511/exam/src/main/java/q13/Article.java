package q13;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Map;

public class Article implements PostInterface {
    private String articleID;
    private LocalDateTime timeCreated;
    private Map<String, Post> posts;

    public Article(String articleID, LocalDateTime timeCreated) {
        this.articleID = articleID;
        this.timeCreated = timeCreated;
        posts = new java.util.HashMap<String, Post>();
    }

    
    
    /** 
     * @param post
     * @return String: postID
     */
    public String addPost(Post post) {
        return null;
    }

    public void updatePost(String postID, String newContent) {}

    public void deletePost(String postID) {}
}
