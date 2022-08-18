package Behavioral.ObserverPattern.Subscriber;

import java.time.ZonedDateTime;

public interface Subscriber {
    void update(ZonedDateTime date);
}
