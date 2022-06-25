package unsw.blackout.device;

import unsw.utils.Angle;

public class LaptopDevice extends Device {
    private static final int MAX_RANGE = 100000;
    private static final int SPEED = 30;

    public LaptopDevice(String id, String type, Angle position) {
        super(id, type, position, false);
    }

    public LaptopDevice(String id, String type, Angle position, boolean isMoving) {
        super(id, type, position, isMoving);
    }

    public int getSpeed() { return SPEED; }

    public int getMaxRange() { return MAX_RANGE; }
}
