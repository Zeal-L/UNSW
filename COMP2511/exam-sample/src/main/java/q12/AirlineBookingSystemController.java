package q12;

import java.time.LocalDate;
import java.time.LocalDateTime;
import java.util.List;

public class AirlineBookingSystemController {
    private List<Booking> bookings;
    private List<Flight> flights;
    
    /**
     * 
     * @param departure The flight departure time in UTC
     * @param arrival The flight arrival time in UTC
     * @param from The departure location
     * @param to The arrival location
     * @param name The flight identifier (e.g. QF1)
     * @param seats A list of the seats on the flight, where each seat is one of the strings "first", "business", "economy"
     */
    public void addFlight(LocalDateTime departure, LocalDateTime arrival, String from, String to, String name, List<String> seats) {}

    /**
     * @param passengerID The identifier of the passender
     * @param preferredClass "first", "business" or "economy", the seat on the flight should be of this type (doesn't have to be)
     * @param from Departure location
     * @param to Destination
     * @param onDay What day they want the flight on
     * @return The ID of the booking
     */
    public String createBooking(String passengerID, String preferredClass, String from, String to, LocalDate onDay) {
        return null;
    }

    /**
     * @param bookingID The ID of the original booking
     * @param newFlightDay What day  the flight is being changed to
     */
    public void changeBooking(String bookingID, LocalDate newFlightDay) {}

    /**
     * @param bookingID The id of the booking to cancel
     */
    public void cancelBooking(String bookingID) {}

}