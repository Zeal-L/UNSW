package dungeonmania.response.models;

import java.util.List;

public class AnimationQueue {
    private final String when;
    private final String entityId;
    private final List<String> queue;
    private final boolean loop;
    private final double duration;
    
    public AnimationQueue(String when, String entityId, List<String> queue, boolean loop, double duration) {
        this.when = when;
        this.entityId = entityId;
        this.queue = queue;
        this.loop = loop;
        this.duration = duration;
    }

    public String getWhen() {
        return when;
    }

    public String getEntityId() {
        return entityId;
    }

    public List<String> getQueue() {
        return queue;
    }

    public boolean isLoop() {
        return loop;
    }

    public double getDuration() {
        return duration;
    }
}
