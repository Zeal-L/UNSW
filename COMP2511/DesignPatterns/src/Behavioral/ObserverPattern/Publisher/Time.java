package Behavioral.ObserverPattern.Publisher;

import java.time.ZonedDateTime;
import java.util.ArrayList;
import java.util.List;

import Behavioral.ObserverPattern.Subscriber.Subscriber;

public class Time implements Publisher {
    private ZonedDateTime date;
    private List<Subscriber> subscribers;
    
    public Time(ZonedDateTime date) {
        this.date = date;
        subscribers = new ArrayList<Subscriber>();
    }

    public void setTime(ZonedDateTime date) {
        this.date = date;
        notifySubscribers();
    }

    public ZonedDateTime getTime() {
        return date;
    }
    
    public void subscribe(Subscriber subscriber) {
        subscribers.add(subscriber);
    }
    
    public void unsubscribe(Subscriber subscriber) {
        subscribers.remove(subscriber);
    }
    
    public void notifySubscribers() {
        subscribers.stream().forEach(subscriber -> subscriber.update(date));
    }
}

