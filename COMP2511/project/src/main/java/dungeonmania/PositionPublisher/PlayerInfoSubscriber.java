package dungeonmania.PositionPublisher;

import dungeonmania.PlayerMode.PlayerMode;
import dungeonmania.util.Position;

public interface PlayerInfoSubscriber {
    void updatePosition(Position position, PlayerMode mode);
}
