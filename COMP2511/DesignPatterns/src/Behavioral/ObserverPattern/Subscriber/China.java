package Behavioral.ObserverPattern.Subscriber;

import java.time.ZoneId;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;

public class China implements Subscriber {
    private ZonedDateTime date;
    
    public China(ZonedDateTime date) {
        this.date = date;
    }
    
    @Override
    public void update(ZonedDateTime date) {
        this.date = date;
    }

    public void reportTime() {
        System.out.print("China's time is ");
        if (! date.getZone().equals(ZoneId.of("Asia/Shanghai"))) {
            date = date.withZoneSameInstant(ZoneId.of("Asia/Shanghai"));
        }
        System.out.println(date.format(DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss")));
    }
}