package hotel;

import java.time.LocalDate;

import org.json.JSONObject;

public class Booking {
    
    LocalDate arrival;
    LocalDate departure;

    public Booking(LocalDate arrival, LocalDate departure) {
        this.arrival = arrival;
        this.departure = departure;
    }

    /**
     * @return a JSONObject of the form {"arrival": arrival, "departure": departure}
     */
    public JSONObject toJSON() {
        JSONObject booking = new JSONObject();
        booking.put("arrival", arrival.toString());
        booking.put("departure", departure.toString());

        return booking;
    }

    /**
     * Checks whether two dates overlap
     * @param start
     * @param end
     */
    public boolean overlaps(LocalDate start, LocalDate end) {
        return start.isBefore(departure) && end.isAfter(arrival);
    }

}