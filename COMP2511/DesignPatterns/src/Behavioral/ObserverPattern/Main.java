package Behavioral.ObserverPattern;

import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;

import Behavioral.ObserverPattern.Publisher.Time;
import Behavioral.ObserverPattern.Subscriber.Australia;
import Behavioral.ObserverPattern.Subscriber.China;

public class Main {
    public static void main(String[] args) {
        
        Time time = new Time(ZonedDateTime.now());
        China china = new China(time.getTime());
        Australia australia = new Australia(time.getTime());
        time.subscribe(china);
        time.subscribe(australia);
        
        china.reportTime();
        australia.reportTime();
        System.out.println("\n-------- After resetting time --------\n");

        LocalDateTime newTime = LocalDateTime.of(1998, 3, 13, 18, 30, 0);
        time.setTime(ZonedDateTime.of(newTime, ZoneOffset.UTC));
        china.reportTime();
        australia.reportTime();

        System.out.println("\n-------- resetting time After unsubscribe australia --------\n");
        time.unsubscribe(australia);
        LocalDateTime newTime2 = LocalDateTime.of(2010, 5, 5, 18, 30, 0);
        time.setTime(ZonedDateTime.of(newTime2, ZoneOffset.UTC));
        china.reportTime();
        australia.reportTime();

    }
}
