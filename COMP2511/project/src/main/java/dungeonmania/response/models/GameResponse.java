package dungeonmania.response.models;

import java.time.LocalDateTime;

public final class GameResponse {
    private final String dungeonId;
    private final String name;
    private final LocalDateTime lastSaved;
    
    public GameResponse(String dungeonId, String name, LocalDateTime lastSaved) {
        this.dungeonId = dungeonId;
        this.name = name;
        this.lastSaved = lastSaved;
    }

    public final LocalDateTime getLastSaved() {
        return lastSaved;
    }

    public final String getGameId() {
        return name;
    }

    public final String getDungeonId() {
        return dungeonId;
    }
}
