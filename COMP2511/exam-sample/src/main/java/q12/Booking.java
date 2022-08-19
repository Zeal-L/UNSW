package q12;

import java.time.LocalDate;

public class Booking {
    public String passengerID;
    public String preferredClass;
    public String from;
    public String to;
    public LocalDate onDay;

    public Booking(String passengerID, String preferredClass, String from, String to, LocalDate onDay) {
        this.passengerID = passengerID;
        this.preferredClass = preferredClass;
        this.from = from;
        this.to = to;
        this.onDay = onDay;
    }

    
    /** 
     * @return String
     */
    public String getPassengerID() {
        return passengerID;
    }

    
    /** 
     * @param passengerID
     */
    public void setPassengerID(String passengerID) {
        this.passengerID = passengerID;
    }

    
    /** 
     * @return String
     */
    public String getPreferredClass() {
        return preferredClass;
    }

    
    /** 
     * @param preferredClass
     */
    public void setPreferredClass(String preferredClass) {
        this.preferredClass = preferredClass;
    }

    
    /** 
     * @return String
     */
    public String getFrom() {
        return from;
    }

    
    /** 
     * @param from
     */
    public void setFrom(String from) {
        this.from = from;
    }

    
    /** 
     * @return String
     */
    public String getTo() {
        return to;
    }

    
    /** 
     * @param to
     */
    public void setTo(String to) {
        this.to = to;
    }

    
    /** 
     * @return LocalDate
     */
    public LocalDate getOnDay() {
        return onDay;
    }

    
    /** 
     * @param onDay
     */
    public void setOnDay(LocalDate onDay) {
        this.onDay = onDay;
    }
    
}
