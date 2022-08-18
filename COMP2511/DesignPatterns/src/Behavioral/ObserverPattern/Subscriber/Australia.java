package Behavioral.ObserverPattern.Subscriber;

import java.time.ZoneId;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;

public class Australia implements Subscriber {
    private ZonedDateTime date;
    
    public Australia(ZonedDateTime date) {
        this.date = date;
    }
    
    @Override
    public void update(ZonedDateTime date) {
        this.date = date;
    }

    public void reportTime() {
        System.out.print("Australia's time is ");
        if (! date.getZone().equals(ZoneId.of("Australia/Sydney"))) {
            date = date.withZoneSameInstant(ZoneId.of("Australia/Sydney"));
        }
        System.out.println(date.format(DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss")));
    }
}
    
