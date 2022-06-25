package unsw.utils;

import java.util.Objects;

/**
 * Represents a generic 'angle' that is either degrees or radians
 * and allows comparison between them.
 * 
 * You shouldn't modify this file.
 * 
 * @author Braedon Wooding
 */
public final class Angle {
    // Internally we store everything as radians.
    private final double radians;

    /**
     * Default initialise the angle to 0.
     */
    public Angle() {
        radians = 0;
    }

    private Angle(double radians) {
        this.radians = radians;
    }

    /**
     * Create an angle from radians.
     */
    public static Angle fromRadians(double radians) {
        return new Angle(radians);
    }

    /**
     * Create an angle from degrees.
     */
    public static Angle fromDegrees(double degrees) {
        return new Angle(Math.toRadians(degrees));
    }

    /**
     * Convert the angle to degrees.
     */
    public final double toDegrees() {
        return Math.toDegrees(radians);
    }

    /**
     * Convert the angle to radians.
     */
    public final double toRadians() {
        return radians;
    }

    @Override
    public final String toString() {
        // All angles are shown to users as degrees
        return Double.toString(toDegrees());
    }

    /**
     * Compare this angle to another angle.
     * Returns...
     * 1  if this is greater than other
     * 0  if this is equal to other
     * -1 if this is less than other
     */
    public int compareTo(Angle other) {
        return Double.compare(this.radians, other.radians);
    }

    /**
     * Add another angle to this angle and return a new angle
     * representing the result.
     */
    public Angle add(Angle other) {
        return Angle.fromRadians(this.radians + other.radians);
    }

    /**
     * subtract another angle from this angle and return a new angle
     * representing the result.
     */
    public Angle subtract(Angle other) {
        return Angle.fromRadians(this.radians - other.radians);
    }

    @Override
    public int hashCode() {
        return Objects.hash(radians);
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (obj == null)
            return false;
        if (getClass() != obj.getClass())
            return false;

        Angle other = (Angle) obj;
        return radians == other.radians;
    }
}
