package hotel;

import java.time.LocalDate;
import java.util.ArrayList;

import org.json.JSONObject;

/**
 * BookingSystemController
 * 
 * @author Nick Patrikeos
 */
public class BookingSystemController {
    
    private ArrayList<Hotel> hotels = new ArrayList<Hotel>();

    /**
     * Creates a new hotel
     * @param hotelName
     */
    public void createHotel(String hotelName) {
        Hotel hotel = new Hotel(hotelName);
        hotels.add(hotel);
    }

    /**
     * Adds a room to the hotel with the given name.
     * @param hotelName
     * @param roomType
     */
    public void addRoom(String hotelName, String roomType) {
        Hotel hotel = findHotel(hotelName);
        hotel.addRoom(roomType);
    }

    /**
     * Makes a booking at the hotel with the given name with the given requirements.
     * @param hotelName
     * @param arrival
     * @param departure
     * @param standard - does the client want a standard room?
     * @param ensuite - does the client want an ensuite room?
     * @param penthouse - does the client want a penthouse room?
     * @return Whether the booking was successfully made
     */
    public boolean makeBooking(String hotelName, LocalDate arrival, LocalDate departure, boolean standard, boolean ensuite, boolean penthouse) {
        Hotel hotel = findHotel(hotelName);
        return hotel.makeBooking(arrival, departure, standard, ensuite, penthouse);
    }

    /**
     * @param hotelName
     * @return The JSON representation of a hotel
     */
    public JSONObject hotelJSON(String hotelName) {
        Hotel hotel = findHotel(hotelName);
        return hotel.toJSON();
    }

    /**
     * Finds a hotel by name
     */
    private Hotel findHotel(String hotelName) {
        return hotels.stream().filter(h -> h.getName().equals(hotelName)).findFirst().get();
    }
}