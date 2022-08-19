package dungeonmania.StaticEntities;

import java.util.ArrayList;
import java.util.List;

import dungeonmania.Entity;
import dungeonmania.Triggerable;
import dungeonmania.TiggerPublisher.TriggerPublisher;
import dungeonmania.TiggerPublisher.TriggerSubscriber;
import dungeonmania.util.Position;

public class FloorSwitch extends StaticEntities implements Triggerable, TriggerPublisher {
    private boolean isOn;
    private final List<TriggerSubscriber> subscribers;

    public FloorSwitch(int x, int y, String type) {
        super(type, false, false, new Position(x, y));
        subscribers = new ArrayList<>();
        isOn = false;
    }
    @Override
    public void triggerEffect(Entity entity) {
        if (entity instanceof Boulder) {
            isOn = true;
            notifySubscribers();
        }
    }

    public boolean checkIsOn() {
        return isOn;
    }

    public void setIsOn(boolean isOn) {
        this.isOn = isOn;
    }

    @Override
    public void subscribe(TriggerSubscriber subscriber) {
        subscribers.add(subscriber);
    }

    @Override
    public void unsubscribe(TriggerSubscriber subscriber) {
        subscribers.remove(subscriber);
    }

    @Override
    public boolean isTriggered() {
        return isOn;
    }

    @Override
    public void notifySubscribers() {
        subscribers.forEach(s -> s.trigger());
    }
}
