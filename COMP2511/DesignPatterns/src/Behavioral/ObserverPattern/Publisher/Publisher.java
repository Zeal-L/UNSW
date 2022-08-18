package Behavioral.ObserverPattern.Publisher;

import Behavioral.ObserverPattern.Subscriber.Subscriber;

public interface Publisher {
    void subscribe(Subscriber subscriber);
    void unsubscribe(Subscriber subscriber);
    void notifySubscribers();
    
}
