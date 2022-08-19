package q13;

import java.time.LocalDateTime;
import java.util.List;

public class Post {

    private String content;
    private LocalDateTime timeCreated;
    private List<String> comments;
    
    public Post(String content, LocalDateTime timeCreated) {
        this.content = content;
        this.timeCreated = timeCreated;
        comments = new java.util.ArrayList<String>();
    }
    
    public void addComment(String comment) {}
    
    public void updatePost(String newContent) {}
    
    public void deletePost() {}
    
}
