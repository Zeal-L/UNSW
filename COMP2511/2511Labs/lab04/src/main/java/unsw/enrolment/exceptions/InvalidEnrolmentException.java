package unsw.enrolment.exceptions;

/**
 * An invalid enrolment.
 * @author Nick Patrikeos
 */
public class InvalidEnrolmentException extends Exception {
    public InvalidEnrolmentException(String message) {
        super(message);
    }
}