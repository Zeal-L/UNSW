package unsw.utils;

/**
 * Represents some generic methods to handle most of the complicated
 * math for you.
 * 
 * You shouldn't modify this file.
 * 
 * @author Braedon Wooding
 */
public final class MathsHelper {
    public static final double RADIUS_OF_JUPITER = 69_911;
    // 2022T2: change default direction to closewise and closkwise is -1
    public static final int CLOCKWISE = -1;
    public static final int ANTI_CLOCKWISE = 1;

    /**
     * Determine the distance between a satellite and another satellite.
     */
    public static double getDistance(double satelliteHeight, Angle satelliteAngle, double otherHeight,
            Angle otherAngle) {
        // convert to euclidean
        double satX = Math.cos(satelliteAngle.toRadians()) * satelliteHeight,
                satY = Math.sin(satelliteAngle.toRadians()) * satelliteHeight;
        double otherX = Math.cos(otherAngle.toRadians()) * otherHeight,
                otherY = Math.sin(otherAngle.toRadians()) * otherHeight;

        // find length of line between euclidean points
        double length = Math.sqrt((satX - otherX) * (satX - otherX) + (satY - otherY) * (satY - otherY));
        return length;
    }

    /**
     * Determine the distance between a satellite and a device.
     */
    public static double getDistance(double satelliteHeight, Angle satelliteAngle, Angle deviceAngle) {
        return getDistance(satelliteHeight, satelliteAngle, RADIUS_OF_JUPITER, deviceAngle);
    }

    /**
     * Determine if a satellite is visible to a device.
     */
    public static boolean isVisible(double satelliteHeight, Angle satelliteAngle, Angle deviceAngle) {
        return isVisible(satelliteHeight, satelliteAngle, RADIUS_OF_JUPITER + 50, deviceAngle);
    }

    /**
     * Determine if a satellite is visible to another satellite.
     */
    public static boolean isVisible(double satelliteHeight, Angle satelliteAngle, double otherHeight,
            Angle otherAngle) {
        // convert to euclidean
        double satX = Math.cos(satelliteAngle.toRadians()) * satelliteHeight,
                satY = Math.sin(satelliteAngle.toRadians()) * satelliteHeight;
        double otherX = Math.cos(otherAngle.toRadians()) * otherHeight,
                otherY = Math.sin(otherAngle.toRadians()) * otherHeight;

        // now is the *fun* part since we have to determine visibility to other
        // satellites this is much more complicated
        // (if it's just to things that always lie on the circle it's just dist <
        // satelliteHeight).
        // Furthermore we can't extrapolate to this an infinite line without a ton of
        // cases... so no point.
        /*
         * == Here be Math ==
         * - Let A = (ax, ay), B = (bx, by) be the points on our line segment
         * - Our cicle C is presumed to be (0, 0) (i.e. centred)
         * - Giving us points of x + y = RADIUS_OF_JUPITER^2
         * 
         * We can then interpolate over the reals for t \in [0, 1] stating that
         * all points on the line must be A + t(B - A).
         * 
         * Points of intersection must satisfy both points at the same time.
         * that is splitting the equations into components and then placing the
         * result into the circle equation.
         * 
         * x = ax + t(bx - ax)
         * y = ay + t(by - ay)
         * 
         * (placing result into circle equation)
         * (ax + t(bx - ax))^2 + (ay + t(by - ay))^2 = RADIUS_OF_JUPITER^2
         * 
         * expanding...
         * t^2[(bx - ax)^2 + (by - ay)^2] + 2t[ax(bx - ax) + ay(by - ay)] + (ax^2 + ay^2
         * - RADIUS_OF_JUPITER^2) = 0
         * which is just a quadratic, we can solve this for t by noting a previous
         * restriction...
         * 'over the *REALS* for t \in [0, 1]'. That is we can determine that indeed t
         * is real
         * and then after that validate it is within [0, 1].
         * 
         * Determinant is b^2 - 4ac, and to ensure t is real this just has to be
         * positive.
         * 
         * ... f u n
         */
        // renaming variables to match equations
        double ax = satX, ay = satY;
        double bx = otherX, by = otherY;

        // t^2 component == (bx - ax)^2 + (by - ay)^2
        double a = (bx - ax) * (bx - ax) + (by - ay) * (by - ay);

        // t component == 2[ax(bx - ax) + ay(by - ay)]
        double b = 2 * (ax * (bx - ax) + ay * (by - ay));

        // t^0 component == ax^2 + ay^2 - RADIUS_OF_JUPITER^2
        double c = ax * ax + ay * ay - RADIUS_OF_JUPITER * RADIUS_OF_JUPITER;

        // det = b^2 - 4ac
        double det = b * b - 4 * a * c;

        // non-real t
        if (det <= 0)
            return true;

        // calculate 2 possible t's
        double sqrtDet = Math.sqrt(det);

        // (-b + sqrtDet)/2a
        double tPos = (-b + sqrtDet) / (2 * a);
        double tNeg = (-b - sqrtDet) / (2 * a);

        // in our specific case we are going to only allow t \in [0, 1]
        // because we are okay with it being the tangent, just not going *through*
        return !((0 <= tPos && tPos <= 1) || (0 <= tNeg && tNeg <= 1));
    }
}
