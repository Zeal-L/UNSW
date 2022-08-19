package q15.expect;

public class ExpectationFailedException extends RuntimeException {
    public ExpectationFailedException(String message) {
        super(message);
    }
}