package unsw.blackout.satellite;

import java.util.ArrayList;

import unsw.blackout.device.Device;
import unsw.utils.Angle;

public class RelaySatellite extends Satellite {

    // Moves at a linear velocity of 1,500 kilometres (1,500,000 metres) per minute
    private static final int SPEED = 1500;
    // Max range of 300,000 kilometres (300,000,000 metres)
    private static final int MAX_RANGE = 300000;
    private boolean clockwise;

    public RelaySatellite(String id, String type, double height, Angle position) {
        super(id, type, height, position, Integer.MAX_VALUE, Integer.MAX_VALUE);
        clockwise = true;
    }

    public int getSpeed() { return SPEED; }

    public int getMaxRange() { return MAX_RANGE; }

    // Cannot store any files
    public boolean checkFileCapacity(int size) {
        return false;
    }

    @Override
    public void simulate(ArrayList<Device> devices, ArrayList<Satellite> satellites) {
        if (getPosition().toDegrees() < 140 && getPosition().toDegrees() >= 0 || 
            getPosition().toDegrees() >= 345 && getPosition().toDegrees() <= 360) {
            setPosition(getPosition().add(Angle.fromRadians(SPEED / getHeight())));
            if (getPosition().toDegrees() >= 360) {
                setPosition(Angle.fromDegrees(getPosition().toDegrees() - 360));
            }
            clockwise = false;

        } else if (getPosition().toDegrees() > 190 && getPosition().toDegrees() < 345) {
            setPosition(getPosition().subtract(Angle.fromRadians(SPEED / getHeight())));
            clockwise = true;

        } else {
            if (clockwise) {
                setPosition(getPosition().subtract(Angle.fromRadians(SPEED / getHeight())));
                if (getPosition().toDegrees() <= 140) 
                    clockwise = false;
                    
            } else {
                setPosition(getPosition().add(Angle.fromRadians(SPEED / getHeight())));
                if (getPosition().toDegrees() >= 190) clockwise = true;
            }
        }
    }

}
