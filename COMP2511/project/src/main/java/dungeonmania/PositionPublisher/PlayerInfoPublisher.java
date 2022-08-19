package dungeonmania.PositionPublisher;

public interface PlayerInfoPublisher {
    void subscribe(PlayerInfoSubscriber subscriber);
    void unsubscribe(PlayerInfoSubscriber subscriber);
    void notifySubscribers();

}
