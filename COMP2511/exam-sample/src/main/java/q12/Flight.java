package q12;

import java.time.LocalDateTime;
import java.util.List;

public class Flight implements Flying {
    private LocalDateTime departure;
    private LocalDateTime arrival;
    private String from;
    private String to;
    private String name;
    private List<String> seats;
    
    public Flight(LocalDateTime departure, LocalDateTime arrival, String from, String to, String name, List<String> seats) {
        this.departure = departure;
        this.arrival = arrival;
        this.from = from;
        this.to = to;
        this.name = name;
        this.seats = seats;
    }
    public LocalDateTime getDeparture() {
        return departure;
    }
    public void setDeparture(LocalDateTime departure) {
        this.departure = departure;
    }
    public LocalDateTime getArrival() {
        return arrival;
    }
    public void setArrival(LocalDateTime arrival) {
        this.arrival = arrival;
    }
    public String getFrom() {
        return from;
    }
    public void setFrom(String from) {
        this.from = from;
    }
    public String getTo() {
        return to;
    }
    public void setTo(String to) {
        this.to = to;
    }
    public String getName() {
        return name;
    }
    public void setName(String name) {
        this.name = name;
    }
    public List<String> getSeats() {
        return seats;
    }
    public void setSeats(List<String> seats) {
        this.seats = seats;
    }
    
}
