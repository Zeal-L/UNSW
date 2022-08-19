package hotel;

import java.time.LocalDate;

import org.json.JSONObject;

public class PenthouseRoom extends Room {
    
    public Booking book(LocalDate arrival, LocalDate departure) {
        return super.book(arrival, departure);
    }

    public JSONObject toJSON() {
        return super.toJSON();
    }

    public void printWelcomeMessage() {
        System.out.println("Welcome to your penthouse apartment, complete with ensuite, lounge, kitchen and master bedroom.");
    }
}