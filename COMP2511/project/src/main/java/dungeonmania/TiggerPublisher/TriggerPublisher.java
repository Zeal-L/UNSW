package dungeonmania.TiggerPublisher;

public interface TriggerPublisher {
    void subscribe(TriggerSubscriber subscriber);
    void unsubscribe(TriggerSubscriber subscriber);
    boolean isTriggered();
    void notifySubscribers();
}
