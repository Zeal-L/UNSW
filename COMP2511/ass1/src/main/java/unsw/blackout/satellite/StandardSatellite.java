package unsw.blackout.satellite;

import java.util.ArrayList;

import unsw.blackout.File;
import unsw.blackout.device.Device;
import unsw.utils.Angle;

public class StandardSatellite extends Satellite {
    // Moves at a linear speed of 2,500 kilometres (2,500,000 metres) per minute
    private static final int SPEED = 2500;
    // Maximum range of 150,000 kilometres (150,000,000 metres)
    private static final int MAX_RANGE = 150000;
    private static final int MAX_CAPACITY = 80;

    public StandardSatellite(String id, String type, double height, Angle position) {
        super(id, type, height, position, 1, 1);
    }

    public int getSpeed() { return SPEED; }

    public int getMaxRange() { return MAX_RANGE; }

    // Can store up to either 3 files or 80 bytes (whichever is smallest for the current situation).
    public boolean checkFileCapacity(int size) {
        if (getFiles().size() >= 3) return false;
        int count = 0;
        
        for (File file : getFiles().values()) {
            count += file.getFileSize();
        }
        if (count + size > MAX_CAPACITY) return false;
        return true;
    }

    @Override
    public void simulate(ArrayList<Device> devices, ArrayList<Satellite> satellites) {
        setPosition(getPosition().subtract(Angle.fromRadians(SPEED / getHeight())));
        
        if (getPosition().toRadians() >= Math.PI * 2) {
            setPosition(Angle.fromRadians(getPosition().toRadians() - Math.PI * 2));
        } else if (getPosition().toRadians() < 0) {
            setPosition(Angle.fromRadians(getPosition().toRadians() + Math.PI * 2));
        }
        super.simulate(devices, satellites);
    }

}