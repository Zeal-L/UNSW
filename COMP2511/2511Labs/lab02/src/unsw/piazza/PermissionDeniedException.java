package unsw.piazza;

/**
 * Permission denied exception.
 */
public class PermissionDeniedException extends Exception {
    public PermissionDeniedException(String errorMessage) {
        super(errorMessage);
    }
}