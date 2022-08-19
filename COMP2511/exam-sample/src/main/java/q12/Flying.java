package q12;

import java.time.LocalDateTime;

public interface Flying {
    LocalDateTime getDeparture();
    void setDeparture(LocalDateTime departure);
    LocalDateTime getArrival();
    void setArrival(LocalDateTime arrival);
}
