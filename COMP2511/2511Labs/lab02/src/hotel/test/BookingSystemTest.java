package hotel.test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import java.time.LocalDate;

import org.json.JSONArray;
import org.json.JSONObject;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.skyscreamer.jsonassert.JSONAssert;

import hotel.BookingSystemController;

/**
 * A series of tests for the BookingSystem
 * 
 * @author Nick Patrikeos
 */
public class BookingSystemTest {

    private final String hotelName = "The Grand Budapest Hotel";
    private final LocalDate bookingStart = LocalDate.of(2020, 4, 21);
    private final LocalDate bookingEnd = LocalDate.of(2020, 5, 6);

    @Nested
    public class RefactoringRegressionTests {
        // Keep these tests passing for the refactoring parts of the lab
        
        @Test
        public void testMakeBooking() {
            BookingSystemController controller = new BookingSystemController();
            controller.createHotel(hotelName);
            controller.addRoom(hotelName, "standard");
            controller.addRoom(hotelName, "ensuite");
            controller.addRoom(hotelName, "penthouse");
            
            // Make a booking
            boolean success = controller.makeBooking(hotelName, bookingStart, bookingEnd, true, false, false); 
            assertTrue(success);
        }

        @Test
        public void testCanMakeTwoBookingsWithoutOverlap() {
            BookingSystemController controller = new BookingSystemController();
            controller.createHotel(hotelName);
            controller.addRoom(hotelName, "standard");
            
            // Make a booking
            controller.makeBooking(hotelName, bookingStart, bookingEnd, true, false, false); 

            // Make a second booking at a completely seperate time/date
            boolean success = controller.makeBooking(hotelName, LocalDate.of(2021, 4, 21), LocalDate.of(2021, 5, 6), true, false, false); 
            assertTrue(success);
        }

        @Test
        public void testCanMakeTwoBookingsAtSameTimeWithMultipleRooms() {
            BookingSystemController controller = new BookingSystemController();
            controller.createHotel(hotelName);
            controller.addRoom(hotelName, "standard");
            controller.addRoom(hotelName, "ensuite");
            
            // Make a booking
            controller.makeBooking(hotelName, bookingStart, bookingEnd, true, false, false); 

            // Make a second booking at the same time/date
            boolean success = controller.makeBooking(hotelName, bookingStart, bookingEnd, true, true, false); 
            assertTrue(success);
        }
    }

    @Nested
    public class Task5OverlapsTests {
        @Test
        public void testBookingsCannotOverlapSameBooking() {
            BookingSystemController controller = new BookingSystemController();
            controller.createHotel(hotelName);
            controller.addRoom(hotelName, "standard");
            controller.addRoom(hotelName, "ensuite");
            controller.addRoom(hotelName, "penthouse");
            
            // Make a booking
            controller.makeBooking(hotelName, bookingStart, bookingEnd, true, false, false); 

            // Make a second booking at the same time/date
            boolean success = controller.makeBooking(hotelName, LocalDate.of(2020, 4, 21), LocalDate.of(2020, 5, 6), true, false, false); 
            assertFalse(success);
        }

        @Test
        public void testOverlapOnStart() {
            BookingSystemController controller = new BookingSystemController();
            controller.createHotel(hotelName);
            // Only one room to book into
            controller.addRoom(hotelName, "standard");
            
            // Make a booking
            controller.makeBooking(hotelName, bookingStart, bookingEnd, true, false, false); 

            // Make a second booking 
            // Starts earlier but finishes after the start
            boolean success = controller.makeBooking(hotelName, LocalDate.of(2020, 3, 1), LocalDate.of(2020, 4, 30), true, false, false); 
            assertFalse(success);
        }

        @Test
        public void testOverlapOnEnd() {
            BookingSystemController controller = new BookingSystemController();
            controller.createHotel(hotelName);
            // Only one room to book into
            controller.addRoom(hotelName, "standard");
            
            // Make a booking
            controller.makeBooking(hotelName, bookingStart, bookingEnd, true, false, false); 

            // Make a second booking 
            // Starts before the first finishes, but finishes later
            boolean success = controller.makeBooking(hotelName, LocalDate.of(2020, 5, 1), LocalDate.of(2020, 5, 30), true, false, false); 
            assertFalse(success);
        }
    }
    
    @Nested
    public class Task6JSONTests {
        @Test
        public void testHotelJSON() {
            BookingSystemController controller = new BookingSystemController();
            controller.createHotel(hotelName);
    
            JSONObject expected = new JSONObject();
            expected.put("rooms", new JSONArray());
            expected.put("name", hotelName);
    
            JSONObject hotelJSON = controller.hotelJSON(hotelName);
            
            JSONAssert.assertEquals(expected, hotelJSON, true);
        }
    
        @Test
        public void testHotelJSONWithRoom() {
            BookingSystemController controller = new BookingSystemController();
            controller.createHotel(hotelName);
            controller.addRoom(hotelName, "standard");
    
            JSONObject expectedRoom = new JSONObject();
            expectedRoom.put("type", "standard");
            expectedRoom.put("bookings", new JSONArray());
    
            JSONObject expectedHotel = new JSONObject();
            expectedHotel.put("rooms", new JSONArray(new JSONObject[]{expectedRoom}));
            expectedHotel.put("name", hotelName);
    
            JSONObject hotelJSON = controller.hotelJSON(hotelName);
    
            JSONAssert.assertEquals(expectedHotel, hotelJSON, true);
        }
    
        @Test
        public void testMakeBooking() {
            BookingSystemController controller = new BookingSystemController();
            controller.createHotel(hotelName);
            controller.addRoom(hotelName, "standard");
            
            // Make a booking
            controller.makeBooking(hotelName, bookingStart, bookingEnd, true, false, false); 
    
            JSONObject expectedBooking = new JSONObject();
            expectedBooking.put("arrival", "2020-04-21");
            expectedBooking.put("departure", "2020-05-06");
    
            JSONObject expectedRoom = new JSONObject();
            expectedRoom.put("type", "standard");
            expectedRoom.put("bookings", new JSONArray(new JSONObject[]{expectedBooking}));
    
            JSONObject expectedHotel = new JSONObject();
            expectedHotel.put("rooms", new JSONArray(new JSONObject[]{expectedRoom}));
            expectedHotel.put("name", hotelName);
    
            JSONObject hotelJSON = controller.hotelJSON(hotelName);
    
            JSONAssert.assertEquals(expectedHotel, hotelJSON, true);
        }
    }
}